# Telegram Multi-User GitHub Repository Manager

A Python Telegram bot that lets each Telegram user connect their own GitHub account, browse/create repositories, and upload ZIP contents to a selected branch.

## Features

- Per-Telegram-user GitHub credentials stored as plain text in SQLite (no encryption key required).
- GitHub token verification and username matching.
- Delete token message where Telegram permissions allow; tokens are never echoed.
- SQLite persistence; reconnect and disconnect support.
- Paginated repository browsing and details.
- Create public/private repositories, optionally initialized with a README.
- ZIP validation, traversal/symlink checks, size/file-count limits, wrapper-directory flattening, and directory structure preservation.
- Repository selection from the account's accessible repositories or a validated manual GitHub URL.
- Branch selection, manual branch names, and opt-in branch creation from the default branch.
- Git Data API upload: blobs, one tree, one commit, and a non-force ref update.
- Secret-free logging and per-user isolated sessions.

## Requirements

- Python 3.10 or newer.
- A Telegram bot token from [@BotFather](https://t.me/BotFather).
- A GitHub Personal Access Token for each user. For classic PATs, `repo` is needed for private repository read/write and `public_repo` may be sufficient for public repositories. Fine-grained tokens need access to the target repositories and relevant Contents (read/write) and Metadata (read) permissions. Creating repositories also requires the appropriate account-level repository creation permission.
- Persistent disk for the SQLite database and uploaded temporary files.

## Setup

```bash
git clone <your-repository-url>
cd <project-directory>
python -m venv .venv
source .venv/bin/activate
# Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Open `GitHub.py` and paste your Telegram bot token into the `BOT_TOKEN` line near the top:

```python
BOT_TOKEN = "123456:telegram-bot-token"
```

Then set optional environment variables:

```bash
export DATABASE_PATH="./data/github_manager.sqlite3"
export DEVELOPER_ID="123456789"              # optional Telegram numeric ID
export DEVELOPER_CONTACT="https://t.me/your_contact"  # optional; configure only your real contact
```

Optional limits (bytes unless noted):

```bash
export MAX_ZIP_BYTES=20971520
export MAX_EXTRACTED_BYTES=52428800
export MAX_FILES=1000
export MAX_ZIP_ENTRIES=1500
export MAX_GITHUB_COMMIT_FILES=3000
export LOG_LEVEL=INFO
```

Start the bot:

```bash
python GitHub.py
```

Use `/start` in Telegram.

## GitHub authorization

Each person chooses **🔵 Authorize**, supplies their GitHub username, a Personal Access Token, and their associated email. The bot verifies the token with `GET /user` and checks that the returned login matches the supplied username. The token message is deleted where Telegram allows it (typically when the bot has sufficient chat permissions and the message is recent).

The email is retained as account metadata; GitHub's authenticated `/user` response does not reliably prove a supplied email belongs to the account, because account emails may be private. The bot does not send commits using that email; GitHub attributes commits according to GitHub's normal commit-author rules.

Never share a PAT in a group chat. Run authorization in a private chat with the bot. Prefer fine-grained tokens scoped to only the repositories and permissions needed. Users can disconnect using the disconnect button in the repository list; reconnecting replaces the stored credential.

## Deployment

### Render Background Worker

1. Push these files to a Git repository.
2. Create a **Background Worker** in Render and connect the repository.
3. Build command: `pip install -r requirements.txt`
4. Start command: `python GitHub.py`
5. Edit `BOT_TOKEN` in `GitHub.py`; optionally configure `DATABASE_PATH`, `DEVELOPER_ID`, `DEVELOPER_CONTACT`, and limits.
6. Attach a persistent disk and set `DATABASE_PATH` to a location on that disk, for example `/var/data/github_manager.sqlite3`.
7. Deploy. Do not run multiple polling workers with the same bot token unless you intentionally configure a webhook/multi-instance architecture.

### VPS / Linux

Run in a dedicated service account and use a process supervisor such as systemd. Keep the `.env` file readable only by that account (`chmod 600`). Example systemd service:

```ini
[Unit]
Description=Telegram GitHub Manager Bot
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=telegrambot
WorkingDirectory=/opt/github-manager
EnvironmentFile=/etc/github-manager.env
ExecStart=/opt/github-manager/.venv/bin/python /opt/github-manager/GitHub.py
Restart=always
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ReadWritePaths=/var/lib/github-manager

[Install]
WantedBy=multi-user.target
```

Set `DATABASE_PATH=/var/lib/github-manager/github_manager.sqlite3`, create that directory, and grant write access to the service account. Then enable the service with `systemctl enable --now github-manager`.

### Termux

Install Python in Termux, then:

```bash
pkg update && pkg install python
pip install -r requirements.txt
```

Edit `BOT_TOKEN` in `GitHub.py`, then run `python GitHub.py`. Keep the device awake and ensure Termux has reliable network access.

## Security and operational notes

- GitHub tokens are stored unencrypted in SQLite in this version. Anyone who can read the database or source files may be able to access credentials. Use this only if you accept that security trade-off; restrict file permissions and never publish the database or bot source with a real token.
- Databases from the previous encrypted version are not automatically decrypted. Users must authorize again after upgrading.
- Keep your Telegram bot token private. If it is exposed, revoke it through @BotFather and generate a replacement.
- Use a private one-to-one Telegram chat. The bot cannot guarantee deletion of a credential message in every chat configuration.
- ZIP files are extracted into per-user temporary directories, never executed, and cleaned up after upload/cancel. Restrict host filesystem permissions and use a disk with sufficient free space.
- The default limits are deliberately conservative. GitHub REST API limits, secondary rate limits, permissions, branch protection, repository size, and server resources still apply.
- The Git Data API upload creates blobs and one tree/commit, then advances the branch without force. If another writer updates the branch during the operation, GitHub may reject the final update; retry after refreshing.
- GitHub tree APIs and practical API quotas constrain very large uploads. The bot enforces a file-count cap and should be deployed with suitable memory, disk, and rate-limit monitoring.
- Logs intentionally avoid request headers, token values, and user-supplied credentials. Protect logs and database backups anyway.
- For production at scale, consider webhook deployment, a job queue, per-user upload quotas, malware scanning in an isolated service, and an external secrets manager.

## Telegram keyboard note

Telegram standard reply-keyboard buttons do not support arbitrary background colors. The five main actions use emoji color cues and a two-column layout, with Developer on the final row. Submenus use inline keyboards.

## Files

- `GitHub.py` — bot implementation.
- `requirements.txt` — Python dependencies.
- `README.md` — this guide.
