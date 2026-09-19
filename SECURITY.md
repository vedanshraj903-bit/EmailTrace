# Security

How EmailTrace keeps keys, tokens and personal data out of the repository.

---

## Where secrets live

All keys and tokens go in local env files. These files are git-ignored and are never committed.

| File | Holds | Committed? |
|---|---|---|
| `backend/.env` | `IPINFO_TOKEN`, `MAXMIND_ACCOUNT_ID`, `MAXMIND_LICENSE_KEY` | No |
| `frontend/.env.local` | `VITE_API_BASE` | No |
| `backend/.env.example`, `frontend/.env.example` | Setting names with **empty** secret values | Yes |

To set up, copy the example file and fill in your own values:

```bash
cp backend/.env.example backend/.env
```

**Never put a secret in a `VITE_` variable.** Vite builds these into the JavaScript that runs in the browser, so anyone using the app can read them. Keys belong in `backend/.env` only.

---

## What stays on your machine

`.gitignore` keeps these out of git:

| Path | Contents |
|---|---|
| `.env`, `.env.*` (except `.env.example`) | Keys and tokens |
| `backend/data/emailtrace.db` | Case database: senders, subjects, IPs, results |
| `backend/data/evidence/` | Every uploaded `.eml`, stored in full |
| `backend/data/geoip/*.mmdb` | MaxMind databases (licensed, not for redistribution) |
| `DATASET/` | Training data |
| `backend/.venv/`, `node_modules/` | Installed packages |

Uploaded emails are real people's mail. Don't copy anything out of `backend/data/` into the repository, an issue or a chat.

---

## Personal data settings

In `backend/.env`:

| Setting | Default | Effect |
|---|---|---|
| `MASK_PII` | `false` | When `true`, recipient addresses are masked in results and reports. The stored `.eml` keeps the original. |
| `RETENTION_DAYS` | `180` | Analyses and their stored `.eml` files older than this are deleted at startup. |
| `MAX_UPLOAD_BYTES` | `15728640` | Largest upload accepted (15 MB). |

Test fixtures in `backend/tests/fixtures/` must use made-up addresses only.

---

## Before you commit

```bash
git status                    # .env, .db, .eml under data/ and .mmdb must not appear
git diff --cached             # read what you are about to commit
```

To check the whole history for a specific key, without printing it:

```bash
git log --all -p | grep -qF "<your key>" && echo "LEAKED" || echo "not in history"
```

---

## If a key leaks

Deleting the file in a new commit is **not** enough: the key is still in the history and on GitHub.

1. **Revoke the key first.**
   - IPinfo: [ipinfo.io/account/token](https://ipinfo.io/account/token)
   - MaxMind: *Account → Manage License Keys*
2. Create a new key and put it in `backend/.env`.
3. Restart the backend.
4. If the repository is public, clean the history with [git-filter-repo](https://github.com/newren/git-filter-repo), then force-push.

---

## Reporting a problem

Report security issues privately to the repository owner. Don't open a public issue.
