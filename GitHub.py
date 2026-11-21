#!/usr/bin/env python3
"""
Multi-user Telegram GitHub Manager.

Python 3.10+. Users authorize with their own GitHub PAT. Tokens are stored
without encryption in SQLite; GitHub operations use each Telegram user’s token.
"""
from __future__ import annotations

import asyncio
import base64
import io
import logging
import os
import re
import shutil
import sqlite3
import tempfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlparse, quote

import aiosqlite
import httpx
from telegram import (
    InlineKeyboardButton, InlineKeyboardMarkup, KeyboardButton,
    ReplyKeyboardMarkup, Update,
)
from telegram.constants import ChatAction
from telegram.error import TelegramError
from telegram.ext import (
    Application, ApplicationBuilder, CallbackQueryHandler, CommandHandler,
    ContextTypes, MessageHandler, filters,
)

APP_NAME = "Telegram GitHub Manager"
# Paste your BotFather token between the quotes before starting the bot.
BOT_TOKEN = "PASTE_YOUR_TELEGRAM_BOT_TOKEN_HERE"
GITHUB_API = "https://api.github.com"
GITHUB_API_VERSION = "2022-11-28"
MAIN_BUTTONS = [
    "🟢 Send Zip To Repo", "🔵 Authorize",
    "🔴 Create Repo", "🔵 All Repo",
    "🟢 Developer",
]
MAX_ZIP_BYTES = int(os.getenv("MAX_ZIP_BYTES", str(20 * 1024 * 1024)))
MAX_EXTRACTED_BYTES = int(os.getenv("MAX_EXTRACTED_BYTES", str(50 * 1024 * 1024)))
MAX_FILES = int(os.getenv("MAX_FILES", "1000"))
MAX_ZIP_ENTRIES = int(os.getenv("MAX_ZIP_ENTRIES", "1500"))
MAX_GITHUB_FILE_BYTES = 100 * 1024 * 1024
MAX_GITHUB_COMMIT_FILES = int(os.getenv("MAX_GITHUB_COMMIT_FILES", "3000"))
HTTP_TIMEOUT = httpx.Timeout(30.0, connect=10.0)
logger = logging.getLogger("github_manager")
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

class UserFacingError(Exception):
    """An expected, safe-to-display error."""

@dataclass
class GitHubAccount:
    login: str
    email: str
    token: str

class Database:
    def __init__(self, path: str):
        self.path = path

    async def initialize(self) -> None:
        parent = Path(self.path).expanduser().resolve().parent
        parent.mkdir(parents=True, exist_ok=True)
        async with aiosqlite.connect(self.path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    telegram_id INTEGER PRIMARY KEY,
                    github_login TEXT NOT NULL,
                    github_email TEXT NOT NULL,
                    token_plaintext TEXT,
                    updated_at INTEGER NOT NULL
                )
            """)
            # Migrate databases created by the encrypted version. Existing encrypted
            # credentials cannot be read by this version; users should authorize again.
            async with db.execute("PRAGMA table_info(users)") as cur:
                columns = {row[1] for row in await cur.fetchall()}
            if "token_ciphertext" in columns and "token_plaintext" not in columns:
                await db.execute("""
                    CREATE TABLE users_plaintext (
                        telegram_id INTEGER PRIMARY KEY,
                        github_login TEXT NOT NULL,
                        github_email TEXT NOT NULL,
                        token_plaintext TEXT,
                        updated_at INTEGER NOT NULL
                    )
                """)
                await db.execute("""
                    INSERT INTO users_plaintext(telegram_id, github_login, github_email, token_plaintext, updated_at)
                    SELECT telegram_id, github_login, github_email, NULL, updated_at FROM users
                """)
                await db.execute("DROP TABLE users")
                await db.execute("ALTER TABLE users_plaintext RENAME TO users")
            elif "token_plaintext" not in columns:
                await db.execute("ALTER TABLE users ADD COLUMN token_plaintext TEXT")
            await db.commit()

    async def save(self, user_id: int, login: str, email: str, token: str) -> None:
        async with aiosqlite.connect(self.path) as db:
            await db.execute("""
                INSERT INTO users(telegram_id, github_login, github_email, token_plaintext, updated_at)
                VALUES(?, ?, ?, ?, ?)
                ON CONFLICT(telegram_id) DO UPDATE SET
                    github_login=excluded.github_login,
                    github_email=excluded.github_email,
                    token_plaintext=excluded.token_plaintext,
                    updated_at=excluded.updated_at
            """, (user_id, login, email, token, int(time.time())))
            await db.commit()

    async def get(self, user_id: int) -> GitHubAccount | None:
        async with aiosqlite.connect(self.path) as db:
            async with db.execute(
                "SELECT github_login, github_email, token_plaintext FROM users WHERE telegram_id=?",
                (user_id,),
            ) as cur:
                row = await cur.fetchone()
        if not row or not row[2]:
            return None
        return GitHubAccount(row[0], row[1], row[2])

    async def delete(self, user_id: int) -> None:
        async with aiosqlite.connect(self.path) as db:
            await db.execute("DELETE FROM users WHERE telegram_id=?", (user_id,))
            await db.commit()

class GitHubClient:
    def __init__(self, token: str):
        self.client = httpx.AsyncClient(
            base_url=GITHUB_API,
            timeout=HTTP_TIMEOUT,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": GITHUB_API_VERSION,
                "User-Agent": "Telegram-GitHub-Manager",
            },
        )

    async def close(self):
        await self.client.aclose()

    async def request(self, method: str, path: str, **kwargs) -> Any:
        try:
            response = await self.client.request(method, path, **kwargs)
        except httpx.TimeoutException as exc:
            raise UserFacingError("GitHub request timed out. Please try again.") from exc
        except httpx.RequestError as exc:
            raise UserFacingError("Could not reach GitHub. Please try again shortly.") from exc

        if response.status_code == 403 and (
            response.headers.get("X-RateLimit-Remaining") == "0"
            or "rate limit" in response.text.lower()
        ):
            reset = response.headers.get("X-RateLimit-Reset")
            wait = ""
            if reset and reset.isdigit():
                wait = f" Try again in about {max(1, int(reset) - int(time.time()))} seconds."
            raise UserFacingError("GitHub API rate limit reached." + wait)
        if response.status_code == 404:
            raise UserFacingError("Repository or resource not found, or your token lacks access.")
        if response.status_code in (401,):
            raise UserFacingError("GitHub rejected the token. Please authorize again.")
        if response.status_code == 409:
            raise UserFacingError("GitHub reported a conflict. Refresh the repository/branch and retry.")
        if response.status_code == 422:
            try:
                message = response.json().get("message", "Validation failed")
            except ValueError:
                message = "Validation failed"
            raise UserFacingError(f"GitHub validation error: {message[:300]}")
        if response.is_error:
            raise UserFacingError(f"GitHub API error ({response.status_code}). Please try again.")
        if response.status_code == 204 or not response.content:
            return None
        try:
            return response.json()
        except ValueError as exc:
            raise UserFacingError("GitHub returned an unexpected response.") from exc

    async def authenticated_user(self):
        return await self.request("GET", "/user")

    async def repos(self, page: int = 1, per_page: int = 8):
        return await self.request("GET", "/user/repos", params={
            "visibility": "all", "affiliation": "owner,collaborator,organization_member",
            "sort": "updated", "per_page": per_page, "page": page,
        })

    async def repo(self, owner: str, name: str):
        return await self.request("GET", f"/repos/{owner}/{name}")

    async def branches(self, owner: str, name: str, page: int = 1):
        return await self.request("GET", f"/repos/{owner}/{name}/branches",
                                  params={"per_page": 100, "page": page})

    async def create_repo(self, name: str, description: str, private: bool, readme: bool):
        return await self.request("POST", "/user/repos", json={
            "name": name, "description": description, "private": private,
            "auto_init": readme,
        })

    async def get_ref(self, owner: str, repo: str, branch: str):
        return await self.request("GET", f"/repos/{owner}/{repo}/git/ref/heads/{branch}")

    async def get_commit(self, owner: str, repo: str, sha: str):
        return await self.request("GET", f"/repos/{owner}/{repo}/git/commits/{sha}")

    async def create_blob(self, owner: str, repo: str, content: bytes):
        return await self.request("POST", f"/repos/{owner}/{repo}/git/blobs", json={
            "content": base64.b64encode(content).decode("ascii"), "encoding": "base64",
        })

    async def create_tree(self, owner: str, repo: str, base_tree: str, entries: list[dict]):
        return await self.request("POST", f"/repos/{owner}/{repo}/git/trees", json={
            "base_tree": base_tree, "tree": entries,
        })

    async def create_commit(self, owner: str, repo: str, message: str, tree: str, parent: str):
        return await self.request("POST", f"/repos/{owner}/{repo}/git/commits", json={
            "message": message, "tree": tree, "parents": [parent],
        })

    async def update_ref(self, owner: str, repo: str, branch: str, sha: str):
        return await self.request("PATCH", f"/repos/{owner}/{repo}/git/refs/heads/{quote(branch, safe='')}",
                                  json={"sha": sha, "force": False})

    async def create_branch(self, owner: str, repo: str, branch: str, source_sha: str):
        return await self.request("POST", f"/repos/{owner}/{repo}/git/refs",
                                  json={"ref": f"refs/heads/{branch}", "sha": source_sha})

def main_keyboard() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(
        [[KeyboardButton(MAIN_BUTTONS[0]), KeyboardButton(MAIN_BUTTONS[1])],
         [KeyboardButton(MAIN_BUTTONS[2]), KeyboardButton(MAIN_BUTTONS[3])],
         [KeyboardButton(MAIN_BUTTONS[4])]],
        resize_keyboard=True,
        is_persistent=True,
    )

def inline(rows: list[list[InlineKeyboardButton]]) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(rows)

def safe_branch_name(name: str) -> bool:
    if not name or len(name) > 200 or name.startswith("/") or name.endswith("/") or ".." in name:
        return False
    return not re.search(r"[\s~^:?*\[\\]", name) and not name.endswith(".") and "//" not in name

def parse_github_url(value: str) -> tuple[str, str]:
    parsed = urlparse(value.strip())
    if parsed.scheme != "https" or parsed.hostname not in ("github.com", "www.github.com"):
        raise UserFacingError("Enter a valid HTTPS GitHub repository URL.")
    parts = [p for p in parsed.path.strip("/").removesuffix(".git").split("/") if p]
    if len(parts) != 2 or any(not re.fullmatch(r"[A-Za-z0-9_.-]+", p) for p in parts):
        raise UserFacingError("URL must look like https://github.com/owner/repository.git")
    return parts[0], parts[1]

def inspect_and_extract_zip(data: bytes, destination: Path) -> tuple[list[tuple[str, Path]], int]:
    if len(data) > MAX_ZIP_BYTES:
        raise UserFacingError(f"ZIP exceeds the {MAX_ZIP_BYTES // (1024*1024)} MB upload limit.")
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        infos = archive.infolist()
        if len(infos) > MAX_ZIP_ENTRIES:
            raise UserFacingError("ZIP contains too many archive entries.")
        total = 0
        files: list[tuple[str, Path]] = []
        seen: set[str] = set()
        for info in infos:
            raw = info.filename.replace("\\", "/")
            path = PurePosixPath(raw)
            mode = (info.external_attr >> 16) & 0o170000
            if path.is_absolute() or not raw or any(part in ("", ".", "..") for part in path.parts):
                raise UserFacingError("ZIP contains an unsafe file path.")
            if ":" in path.parts[0] or "\x00" in raw:
                raise UserFacingError("ZIP contains an unsafe file path.")
            if mode == 0o120000:
                raise UserFacingError("ZIP symbolic links are not accepted.")
            normalized = path.as_posix().rstrip("/")
            if normalized in seen:
                raise UserFacingError("ZIP contains duplicate paths.")
            seen.add(normalized)
            if info.is_dir():
                continue
            total += info.file_size
            if total > MAX_EXTRACTED_BYTES:
                raise UserFacingError("ZIP expands beyond the configured extracted-size limit.")
            if info.file_size > MAX_GITHUB_FILE_BYTES:
                raise UserFacingError("A ZIP file exceeds GitHub's 100 MB blob limit.")
        if total == 0:
            raise UserFacingError("ZIP contains no files to upload.")
        archive.extractall(destination)
        roots = {p.parts[0] for p in (PurePosixPath(i.filename.replace("\\", "/")) for i in infos if not i.is_dir())}
        base = destination
        if len(roots) == 1:
            root = destination / next(iter(roots))
            if root.is_dir():
                base = root
        for path in base.rglob("*"):
            if path.is_file():
                rel = path.relative_to(base).as_posix()
                if rel.startswith(".git/") or rel == ".git":
                    raise UserFacingError("ZIP must not contain a .git directory.")
                files.append((rel, path))
        if not files:
            raise UserFacingError("ZIP contains no regular files.")
        if len(files) > MAX_FILES:
            raise UserFacingError(f"ZIP contains more than the {MAX_FILES}-file limit.")
        return files, total
    except zipfile.BadZipFile as exc:
        raise UserFacingError("The uploaded file is not a valid ZIP archive.") from exc
    except (OSError, RuntimeError, EOFError) as exc:
        raise UserFacingError("Could not safely extract this ZIP archive.") from exc

async def send_text(update: Update, text: str, **kwargs):
    if update.effective_message:
        await update.effective_message.reply_text(text, **kwargs)

async def get_account(update: Update, context: ContextTypes.DEFAULT_TYPE) -> GitHubAccount | None:
    appdata = context.application.bot_data
    return await appdata["db"].get(update.effective_user.id)

async def authorized_client(update: Update, context: ContextTypes.DEFAULT_TYPE):
    account = await get_account(update, context)
    if not account:
        await send_text(update, "Please connect your GitHub account first using 🔵 Authorize.")
        return None, None
    return account, GitHubClient(account.token)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data.clear()
    account = await get_account(update, context)
    status = f"Connected to GitHub as @{account.login}." if account else "GitHub account not connected."
    await send_text(update, f"Welcome to {APP_NAME}!\n{status}\n\nChoose an action below.",
                    reply_markup=main_keyboard())

async def begin_authorize(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data.clear()
    context.user_data["flow"] = "auth_username"
    await send_text(update, "Send your GitHub username. Use /cancel to stop.")

async def begin_upload(update: Update, context: ContextTypes.DEFAULT_TYPE):
    account, client = await authorized_client(update, context)
    if not account:
        return
    await client.close()
    context.user_data.clear()
    context.user_data["flow"] = "zip_wait"
    await send_text(update, f"Send a .zip file (maximum {MAX_ZIP_BYTES // (1024*1024)} MB).")

async def begin_create(update: Update, context: ContextTypes.DEFAULT_TYPE):
    account, client = await authorized_client(update, context)
    if not account:
        return
    await client.close()
    context.user_data.clear()
    context.user_data["flow"] = "create_name"
    await send_text(update, "Enter the new repository name. Use /cancel to stop.")

async def show_repos(update: Update, context: ContextTypes.DEFAULT_TYPE, page: int = 1):
    account, client = await authorized_client(update, context)
    if not account:
        return
    try:
        repos = await client.repos(page=page)
        rows = []
        context.user_data["repo_page_items"] = [
            (repo["owner"]["login"], repo["name"]) for repo in repos
        ]
        for index, repo in enumerate(repos):
            rows.append([InlineKeyboardButton(
                f"{'🔒' if repo['private'] else '🌐'} {repo['full_name']}"[:60],
                callback_data=f"repoidx:{index}"
            )])
        nav = []
        if page > 1:
            nav.append(InlineKeyboardButton("⬅️ Previous", callback_data=f"repos:{page-1}"))
        if len(repos) == 8:
            nav.append(InlineKeyboardButton("Next ➡️", callback_data=f"repos:{page+1}"))
        nav.append(InlineKeyboardButton("🔵 Refresh", callback_data="repos:1"))
        if nav:
            rows.append(nav)
        rows.append([InlineKeyboardButton("🔴 Disconnect GitHub", callback_data="disconnect")])
        rows.append([InlineKeyboardButton("🔴 Cancel", callback_data="cancel")])
        await send_text(update, f"Repositories for @{account.login} — page {page}:",
                        reply_markup=inline(rows))
    finally:
        await client.close()

async def show_repo_details(query, context, owner: str, name: str):
    user_id = query.from_user.id
    context.user_data["selected_repo"] = (owner, name)
    account = await context.application.bot_data["db"].get(user_id)
    if not account:
        await query.edit_message_text("Authorize first.")
        return
    client = GitHubClient(account.token)
    try:
        repo = await client.repo(owner, name)
        text = (f"**{repo['full_name']}**\n"
                f"Visibility: {'Private' if repo['private'] else 'Public'}\n"
                f"Default branch: {repo.get('default_branch') or 'Not set'}\n"
                f"URL: {repo['html_url']}")
        await query.edit_message_text(text, parse_mode="Markdown", reply_markup=inline([
            [InlineKeyboardButton("🔵 Refresh", callback_data="reporefresh")],
            [InlineKeyboardButton("🔵 Back to repositories", callback_data="repos:1")],
        ]), disable_web_page_preview=True)
    finally:
        await client.close()

async def begin_repo_selection(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data["flow"] = "zip_repo_choice"
    await send_text(update, "Choose how to select the destination repository:",
                    reply_markup=inline([
                        [InlineKeyboardButton("📂 Select From Bot", callback_data="ziprepos:1")],
                        [InlineKeyboardButton("🔗 Manual Git URL", callback_data="manualurl")],
                        [InlineKeyboardButton("🔴 Cancel", callback_data="cancel")],
                    ]))

async def list_zip_repos(query, context, page: int):
    account = await context.application.bot_data["db"].get(query.from_user.id)
    if not account:
        await query.edit_message_text("Authorize first.")
        return
    client = GitHubClient(account.token)
    try:
        repos = await client.repos(page=page)
        context.user_data["zip_repo_page_items"] = [
            (r["owner"]["login"], r["name"]) for r in repos
        ]
        rows = [[InlineKeyboardButton(
            f"{'🔒' if r['private'] else '🌐'} {r['full_name']}"[:60],
            callback_data=f"ziprepoidx:{i}"
        )] for i, r in enumerate(repos)]
        nav = []
        if page > 1:
            nav.append(InlineKeyboardButton("⬅️ Previous", callback_data=f"ziprepos:{page-1}"))
        if len(repos) == 8:
            nav.append(InlineKeyboardButton("Next ➡️", callback_data=f"ziprepos:{page+1}"))
        if nav:
            rows.append(nav)
        rows.append([InlineKeyboardButton("🔴 Cancel", callback_data="cancel")])
        await query.edit_message_text(f"Choose a repository — page {page}:", reply_markup=inline(rows))
    finally:
        await client.close()

async def choose_repo_for_zip(query, context, owner: str, name: str):
    account = await context.application.bot_data["db"].get(query.from_user.id)
    if not account:
        await query.edit_message_text("Authorize first.")
        return
    client = GitHubClient(account.token)
    try:
        repo = await client.repo(owner, name)
        await prepare_branch_menu(query, context, client, repo)
    finally:
        await client.close()

async def prepare_branch_menu(query, context, client, repo):
    owner, name = repo["owner"]["login"], repo["name"]
    branches = await client.branches(owner, name)
    default = repo.get("default_branch") or (branches[0]["name"] if branches else "")
    context.user_data["target_repo"] = {"owner": owner, "name": name, "private": repo["private"]}
    context.user_data["flow"] = "zip_branch"
    branch_names = []
    if default:
        branch_names.append(default)
    branch_names.extend(b["name"] for b in branches if b["name"] != default)
    context.user_data["branch_choices"] = branch_names[:21]
    rows = []
    if default:
        rows.append([InlineKeyboardButton(f"⭐ Default: {default}"[:60], callback_data="branchidx:0")])
    for index, branch_name in enumerate(branch_names[1:21], start=1):
        rows.append([InlineKeyboardButton(branch_name[:60], callback_data=f"branchidx:{index}")])
    rows.append([InlineKeyboardButton("✍️ Enter branch name", callback_data="branchmanual")])
    rows.append([InlineKeyboardButton("🌱 Create new branch", callback_data="branchnew")])
    rows.append([InlineKeyboardButton("🔴 Cancel", callback_data="cancel")])
    await query.edit_message_text(
        f"Repository: {owner}/{name}\nVisibility: {'Private' if repo['private'] else 'Public'}\nChoose a branch:",
        reply_markup=inline(rows),
    )

async def confirm_upload(query, context, branch: str):
    if not safe_branch_name(branch):
        await query.edit_message_text("Invalid branch name.")
        return
    context.user_data["target_branch"] = branch
    context.user_data["flow"] = "zip_confirm"
    files = context.user_data.get("zip_files", [])
    repo = context.user_data.get("target_repo", {})
    await query.edit_message_text(
        f"Repository: {repo.get('owner')}/{repo.get('name')}\n"
        f"Branch: {branch}\nFiles: {len(files)}\n\n"
        "This will add new files and replace files at matching paths in one Git commit.",
        reply_markup=inline([
            [InlineKeyboardButton("🟢 SEND", callback_data="zipsend")],
            [InlineKeyboardButton("🔵 BACK", callback_data="branchback")],
            [InlineKeyboardButton("🔴 CANCEL", callback_data="cancel")],
        ]),
    )

async def do_upload(query, context):
    user_id = query.from_user.id
    account = await context.application.bot_data["db"].get(user_id)
    files = context.user_data.get("zip_files")
    repo = context.user_data.get("target_repo")
    branch = context.user_data.get("target_branch")
    if not account or not files or not repo or not branch:
        await query.edit_message_text("Upload session expired. Start again.")
        return
    await query.edit_message_text("Preparing upload: creating Git blobs…")
    client = GitHubClient(account.token)
    try:
        owner, name = repo["owner"], repo["name"]
        ref = await client.get_ref(owner, name, branch)
        parent_sha = ref["object"]["sha"]
        parent_commit = await client.get_commit(owner, name, parent_sha)
        base_tree = parent_commit["tree"]["sha"]
        tree_entries = []
        total = len(files)
        for index, (rel, path) in enumerate(files, start=1):
            content = path.read_bytes()
            blob = await client.create_blob(owner, name, content)
            tree_entries.append({"path": rel, "mode": "100644", "type": "blob", "sha": blob["sha"]})
            if index == 1 or index == total or index % 10 == 0:
                try:
                    await query.edit_message_text(f"Uploading… {index}/{total} files processed")
                except TelegramError:
                    pass
        if total > MAX_GITHUB_COMMIT_FILES:
            raise UserFacingError(f"Too many files for one commit ({MAX_GITHUB_COMMIT_FILES} maximum).")
        tree = await client.create_tree(owner, name, base_tree, tree_entries)
        commit = await client.create_commit(owner, name, f"Upload ZIP via {APP_NAME}", tree["sha"], parent_sha)
        await client.update_ref(owner, name, branch, commit["sha"])
        await query.edit_message_text(
            f"🟢 Upload complete!\nRepository: https://github.com/{owner}/{name}\n"
            f"Branch: {branch}\nUploaded files: {total}",
            disable_web_page_preview=True,
            reply_markup=inline([[InlineKeyboardButton("🔵 Main menu", callback_data="home")]]),
        )
        cleanup_user_temp(context)
    finally:
        await client.close()

def cleanup_user_temp(context):
    folder = context.user_data.pop("zip_temp", None)
    if folder:
        shutil.rmtree(folder, ignore_errors=True)
    context.user_data.pop("zip_files", None)

async def begin_manual_url(query, context):
    context.user_data["flow"] = "manual_url"
    await query.edit_message_text("Send the HTTPS GitHub repository URL, for example:\nhttps://github.com/owner/repository.git")

async def begin_create_branch(query, context):
    context.user_data["flow"] = "branch_new_name"
    await query.edit_message_text("Enter the new branch name. It will be created from the repository's default branch.")

async def begin_manual_branch(query, context):
    context.user_data["flow"] = "branch_manual_name"
    await query.edit_message_text("Enter the branch name to use.")

async def callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data = query.data or ""
    try:
        if data == "cancel":
            cleanup_user_temp(context)
            context.user_data.clear()
            await query.edit_message_text("Cancelled.")
        elif data == "home":
            cleanup_user_temp(context)
            context.user_data.clear()
            await query.message.reply_text("Main menu:", reply_markup=main_keyboard())
        elif data.startswith("repos:"):
            await show_repos_from_callback(query, context, int(data.split(":")[1]))
        elif data.startswith("repoidx:"):
            index = int(data.split(":", 1)[1])
            items = context.user_data.get("repo_page_items", [])
            if index < 0 or index >= len(items):
                raise UserFacingError("That repository selection expired. Refresh the list.")
            await show_repo_details(query, context, *items[index])
        elif data == "reporefresh":
            selected = context.user_data.get("selected_repo")
            if not selected:
                raise UserFacingError("That repository selection expired. Refresh the list.")
            await show_repo_details(query, context, *selected)
        elif data.startswith("ziprepos:"):
            await list_zip_repos(query, context, int(data.split(":")[1]))
        elif data.startswith("ziprepoidx:"):
            index = int(data.split(":", 1)[1])
            items = context.user_data.get("zip_repo_page_items", [])
            if index < 0 or index >= len(items):
                raise UserFacingError("That repository selection expired. Please select again.")
            await choose_repo_for_zip(query, context, *items[index])
        elif data.startswith("branchidx:"):
            index = int(data.split(":", 1)[1])
            choices = context.user_data.get("branch_choices", [])
            if index < 0 or index >= len(choices):
                raise UserFacingError("That branch selection expired. Please select again.")
            await confirm_upload(query, context, choices[index])
        elif data == "branchmanual":
            await begin_manual_branch(query, context)
        elif data == "branchnew":
            await begin_create_branch(query, context)
        elif data == "branchback":
            repo = context.user_data.get("target_repo", {})
            account = await context.application.bot_data["db"].get(query.from_user.id)
            if not account:
                await query.edit_message_text("Authorize first.")
                return
            client = GitHubClient(account.token)
            try:
                details = await client.repo(repo["owner"], repo["name"])
                await prepare_branch_menu(query, context, client, details)
            finally:
                await client.close()
        elif data == "zipsend":
            await do_upload(query, context)
        elif data == "manualurl":
            await begin_manual_url(query, context)
        elif data.startswith("visibility:"):
            context.user_data["create_private"] = data.endswith("private")
            context.user_data["flow"] = "create_readme"
            await query.edit_message_text("Initialize repository with a README?",
                reply_markup=inline([[
                    InlineKeyboardButton("Yes", callback_data="readme:yes"),
                    InlineKeyboardButton("No", callback_data="readme:no"),
                ], [InlineKeyboardButton("🔴 Cancel", callback_data="cancel")]]))
        elif data.startswith("readme:"):
            await create_repository_now(query, context, data.endswith("yes"))
        elif data == "disconnect":
            await context.application.bot_data["db"].delete(query.from_user.id)
            await query.edit_message_text("🔴 GitHub account disconnected.")
        elif data == "refresh":
            await show_repos_from_callback(query, context, 1)
    except UserFacingError as exc:
        await query.edit_message_text(str(exc))
    except Exception:
        logger.exception("Callback failed for Telegram user %s", query.from_user.id)
        try:
            await query.edit_message_text("Something went wrong. Please try again.")
        except TelegramError:
            pass

async def show_repos_from_callback(query, context, page):
    account = await context.application.bot_data["db"].get(query.from_user.id)
    if not account:
        await query.edit_message_text("Authorize first.")
        return
    client = GitHubClient(account.token)
    try:
        repos = await client.repos(page)
        context.user_data["repo_page_items"] = [
            (r["owner"]["login"], r["name"]) for r in repos
        ]
        rows = [[InlineKeyboardButton(
            f"{'🔒' if r['private'] else '🌐'} {r['full_name']}"[:60],
            callback_data=f"repoidx:{i}"
        )] for i, r in enumerate(repos)]
        nav = []
        if page > 1: nav.append(InlineKeyboardButton("⬅️ Previous", callback_data=f"repos:{page-1}"))
        if len(repos) == 8: nav.append(InlineKeyboardButton("Next ➡️", callback_data=f"repos:{page+1}"))
        nav.append(InlineKeyboardButton("🔵 Refresh", callback_data="refresh"))
        rows.append(nav)
        rows.append([InlineKeyboardButton("🔴 Disconnect GitHub", callback_data="disconnect")])
        await query.edit_message_text(f"Repositories for @{account.login} — page {page}:",
                                      reply_markup=inline(rows))
    finally:
        await client.close()

async def create_repository_now(query, context, readme: bool):
    account = await context.application.bot_data["db"].get(query.from_user.id)
    if not account:
        await query.edit_message_text("Authorize first.")
        return
    name = context.user_data.get("create_name")
    description = context.user_data.get("create_description", "")
    client = GitHubClient(account.token)
    try:
        repo = await client.create_repo(name, description, context.user_data.get("create_private", False), readme)
        context.user_data.clear()
        await query.edit_message_text(
            f"🟢 Repository created!\nName: {repo['full_name']}\nURL: {repo['html_url']}\n"
            f"Default branch: {repo.get('default_branch') or 'Not initialized'}\n"
            f"Visibility: {'Private' if repo['private'] else 'Public'}",
            disable_web_page_preview=True,
            reply_markup=inline([[InlineKeyboardButton("🔵 Main menu", callback_data="home")]]),
        )
    finally:
        await client.close()

async def receive_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if context.user_data.get("flow") != "zip_wait":
        return
    doc = update.message.document
    if not doc.file_name or not doc.file_name.lower().endswith(".zip"):
        await send_text(update, "Please upload a file with the .zip extension.")
        return
    if doc.file_size and doc.file_size > MAX_ZIP_BYTES:
        await send_text(update, f"ZIP is too large. Maximum: {MAX_ZIP_BYTES // (1024*1024)} MB.")
        return
    temp = Path(tempfile.mkdtemp(prefix=f"tggh_{update.effective_user.id}_"))
    context.user_data["zip_temp"] = str(temp)
    try:
        await update.message.chat.send_action(ChatAction.TYPING)
        tg_file = await context.bot.get_file(doc.file_id)
        buffer = io.BytesIO()
        await tg_file.download_to_memory(out=buffer)
        data = buffer.getvalue()
        files, total = inspect_and_extract_zip(data, temp / "extract")
        context.user_data["zip_files"] = [(name, str(path)) for name, path in files]
        # Convert stored paths back to Path objects for the GitHub uploader.
        context.user_data["zip_files"] = [(name, Path(path)) for name, path in context.user_data["zip_files"]]
        context.user_data["flow"] = "zip_ready"
        await send_text(update, f"🟢 ZIP validated and extracted.\nFiles: {len(files)}\nExpanded size: {total:,} bytes")
        await begin_repo_selection(update, context)
    except UserFacingError as exc:
        cleanup_user_temp(context)
        await send_text(update, str(exc))
    except (TelegramError, OSError) as exc:
        cleanup_user_temp(context)
        logger.warning("ZIP download/extraction failed for user %s: %s", update.effective_user.id, type(exc).__name__)
        await send_text(update, "Could not download or extract that ZIP. Please try again.")
    except Exception:
        cleanup_user_temp(context)
        logger.exception("Unexpected ZIP processing error for user %s", update.effective_user.id)
        await send_text(update, "Could not process that ZIP. Please try again.")

async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (update.message.text or "").strip()
    flow = context.user_data.get("flow")
    if text == "🔵 Authorize":
        await begin_authorize(update, context); return
    if text == "🟢 Send Zip To Repo":
        await begin_upload(update, context); return
    if text == "🔴 Create Repo":
        await begin_create(update, context); return
    if text == "🔵 All Repo":
        await show_repos(update, context); return
    if text == "🟢 Developer":
        dev_id = os.getenv("DEVELOPER_ID", "").strip()
        contact = os.getenv("DEVELOPER_CONTACT", "").strip()
        details = "Developer information"
        if dev_id.isdigit():
            details += f"\nTelegram ID: {dev_id}"
        if contact:
            details += f"\nContact: {contact}"
        if not dev_id and not contact:
            details += "\nDeveloper contact details have not been configured."
        await send_text(update, details, reply_markup=inline([
            [InlineKeyboardButton("🔵 Back", callback_data="home")],
        ])); return

    if not flow:
        await send_text(update, "Choose an option from the menu.", reply_markup=main_keyboard())
        return
    try:
        if flow == "auth_username":
            if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?", text):
                await send_text(update, "That does not look like a valid GitHub username. Try again."); return
            context.user_data["auth_username"] = text
            context.user_data["flow"] = "auth_token"
            await send_text(update, "Send your GitHub Personal Access Token now. The message will be deleted where Telegram permits.")
        elif flow == "auth_token":
            token = text
            try:
                await update.message.delete()
            except TelegramError:
                logger.info("Could not delete credential message for user %s", update.effective_user.id)
            context.user_data["auth_token"] = token
            context.user_data["flow"] = "auth_email"
            await send_text(update, "Now send the email address associated with your GitHub account.")
        elif flow == "auth_email":
            email = text
            if len(email) > 254 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
                await send_text(update, "Please enter a valid email address."); return
            token = context.user_data.pop("auth_token", None)
            username = context.user_data.pop("auth_username", None)
            if not token or not username:
                context.user_data.clear()
                await send_text(update, "Authorization session expired. Start again."); return
            client = GitHubClient(token)
            try:
                user = await client.authenticated_user()
                if user.get("login", "").casefold() != username.casefold():
                    await send_text(update, "The supplied username does not match the authenticated GitHub account. Start authorization again.")
                    context.user_data.clear(); return
                # GitHub does not require the account email to be public; retain the user-supplied address.
                await context.application.bot_data["db"].save(
                    update.effective_user.id, user["login"], email, token)
                context.user_data.clear()
                await send_text(update, f"🟢 Connected successfully as @{user['login']}.")
            finally:
                await client.close()
        elif flow == "manual_url":
            owner, name = parse_github_url(text)
            account, client = await authorized_client(update, context)
            if not account: return
            try:
                repo = await client.repo(owner, name)
                await send_text(update, f"Repository access verified: {repo['full_name']} ({'Private' if repo['private'] else 'Public'}).")
                # Use a synthetic callback-like branch chooser message.
                msg = await update.message.reply_text("Loading branches…")
                fake_query = type("Q", (), {"edit_message_text": msg.edit_text})()
                await prepare_branch_menu(fake_query, context, client, repo)
            finally:
                await client.close()
        elif flow in ("branch_manual_name", "branch_new_name"):
            if not safe_branch_name(text):
                await send_text(update, "Invalid branch name. Enter a valid Git branch name."); return
            repo = context.user_data.get("target_repo", {})
            account, client = await authorized_client(update, context)
            if not account: return
            try:
                if flow == "branch_new_name":
                    details = await client.repo(repo["owner"], repo["name"])
                    default = details.get("default_branch")
                    if not default:
                        raise UserFacingError("Repository has no default branch to branch from.")
                    ref = await client.get_ref(repo["owner"], repo["name"], default)
                    await client.create_branch(repo["owner"], repo["name"], text, ref["object"]["sha"])
                await send_text(update, f"Branch selected: {text}")
                # Confirmation via message with inline controls.
                context.user_data["target_branch"] = text
                context.user_data["flow"] = "zip_confirm"
                files = context.user_data.get("zip_files", [])
                await update.message.reply_text(
                    f"Repository: {repo['owner']}/{repo['name']}\nBranch: {text}\nFiles: {len(files)}",
                    reply_markup=inline([
                        [InlineKeyboardButton("🟢 SEND", callback_data="zipsend")],
                        [InlineKeyboardButton("🔵 BACK", callback_data="branchback")],
                        [InlineKeyboardButton("🔴 CANCEL", callback_data="cancel")],
                    ]))
            finally:
                await client.close()
        elif flow == "create_name":
            if not re.fullmatch(r"[A-Za-z0-9._-]{1,100}", text) or text in (".", ".."):
                await send_text(update, "Repository name may contain letters, numbers, dots, underscores and hyphens."); return
            context.user_data["create_name"] = text
            context.user_data["flow"] = "create_description"
            await send_text(update, "Enter a description, or send - to leave it blank.")
        elif flow == "create_description":
            context.user_data["create_description"] = "" if text == "-" else text[:350]
            context.user_data["flow"] = "create_visibility"
            await send_text(update, "Choose visibility:", reply_markup=inline([
                [InlineKeyboardButton("🌐 Public", callback_data="visibility:public"),
                 InlineKeyboardButton("🔒 Private", callback_data="visibility:private")],
                [InlineKeyboardButton("🔴 Cancel", callback_data="cancel")],
            ]))
    except UserFacingError as exc:
        await send_text(update, str(exc))
    except Exception:
        logger.exception("Message handling failed for Telegram user %s", update.effective_user.id)
        await send_text(update, "Something went wrong. Please try again.")

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    cleanup_user_temp(context)
    context.user_data.clear()
    await send_text(update, "Cancelled.", reply_markup=main_keyboard())

async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE):
    error = context.error
    logger.error("Unhandled update error: %s", type(error).__name__, exc_info=error)

async def post_init(application: Application):
    await application.bot_data["db"].initialize()

async def post_shutdown(application: Application):
    # No persistent shared HTTP clients are kept open.
    pass

def main():
    bot_token = BOT_TOKEN.strip()
    database_path = os.getenv("DATABASE_PATH", "data/github_manager.sqlite3").strip()
    if not bot_token or bot_token == "PASTE_YOUR_TELEGRAM_BOT_TOKEN_HERE":
        raise SystemExit("Open GitHub.py and paste your BotFather token into BOT_TOKEN near the top of the file.")

    application = (
        ApplicationBuilder().token(bot_token)
        .concurrent_updates(False)
        .post_init(post_init)
        .post_shutdown(post_shutdown)
        .build()
    )
    application.bot_data["db"] = Database(database_path)
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("cancel", cancel))
    application.add_handler(CallbackQueryHandler(callback_handler))
    application.add_handler(MessageHandler(filters.Document.ALL, receive_document))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    application.add_error_handler(error_handler)
    logger.info("%s starting", APP_NAME)
    application.run_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=False)

if __name__ == "__main__":
    main()
