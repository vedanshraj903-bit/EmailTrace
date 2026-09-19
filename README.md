# EmailTrace

Upload a suspicious email (`.eml`) and EmailTrace tells you whether it is phishing, spoofed or fraud, where it came from, and why. You get a risk score out of 100, a map of the delivery path, and a PDF report.

---

## What you need

| Tool | Version | Check with |
|---|---|---|
| Python | 3.11 – 3.13 | `python3 --version` |
| Node.js | 20.19+ or 22.12+ | `node --version` |
| Git | any | `git --version` |

---

## Run it (first time)

You need **two terminals**: one for the backend, one for the frontend.

### 1. Get the code

```bash
git clone <repo-url> emailtrace
cd emailtrace
```

### 2. Start the backend (terminal 1)

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env               # Windows: copy .env.example .env
uvicorn app.main:app --reload --port 8000
```

Leave it running. Check it at http://localhost:8000/api/health.

### 3. Start the frontend (terminal 2)

```bash
cd frontend
npm install
npm run dev
```

### 4. Open the app

Go to **http://localhost:5173**, click **Analyze email**, and drop in an `.eml` file.
Two samples are in `backend/tests/fixtures/`.

### Next time

You only need the start commands:

```bash
# terminal 1
cd backend && source .venv/bin/activate && uvicorn app.main:app --reload --port 8000
# terminal 2
cd frontend && npm run dev
```

On Windows, activate with `.venv\Scripts\activate` and run the commands one at a time.

---

## Optional extras

The app works without these. Each one adds detail.

**IP location (recommended).** Get a free token at [ipinfo.io](https://ipinfo.io/signup) and put it in `backend/.env`:
```
IPINFO_TOKEN=your_token
```

**MaxMind accuracy radius.** Create a free [MaxMind](https://www.maxmind.com) account, then generate a licence key under *Account → Manage License Keys* and add:
```
MAXMIND_ACCOUNT_ID=123456
MAXMIND_LICENSE_KEY=your_key
```
The databases download by themselves when the backend starts.

**ML classifier.** The trained model is not in git (it is 26 MB). To build it, put the datasets in a `DATASET/` folder at the project root, then run:
```bash
cd backend && source .venv/bin/activate
python -m ml.train --data ../DATASET/df.csv --data ../DATASET/CEAS_08.csv.zip \
  --external-test ../DATASET/CEAS_08.csv.zip --label-map 0=legitimate,1=malicious,2=malicious
```
This takes about 6 minutes and needs about 6 GB of RAM. Restart the backend afterwards. Any CSV with a label column and a text (or subject/body) column works.

Restart the backend after editing `.env`. The sidebar's **System status** shows what is switched on.

---

## How it works

When you upload an email, the backend:

1. **Seals the evidence.** It saves the original file with its SHA-256 hash and starts a chain-of-custody log.
2. **Reads the headers.** It parses the sender, Reply-To, Return-Path, and every `Received` hop, oldest first.
3. **Checks authentication.** It re-runs SPF, DKIM and DMARC itself and compares the results with what the receiving server recorded.
4. **Finds the origin.** It picks the first public IP in the delivery path and looks up its location (country → state → district → city), network (ASN), reverse DNS, Tor exit status and spam blocklists.
   *Gmail, Outlook.com and Yahoo hide the sender's IP, so for those only the provider's server can be located. The app says so.*
5. **Investigates the domain.** It checks WHOIS age, DNS records, disposable-email lists, and look-alikes of protected brands (for example `paypa1.com`).
6. **Reads the content.** It inspects links and attachments for tricks (mismatched link text, `.pdf.exe`), and the ML classifier plus keyword cues score the wording.
7. **Scores and attributes.** It combines everything into a 0–100 risk score, a verdict (legitimate / suspicious / phishing / impersonation / fraud), and who is likely behind it.
8. **Links campaigns.** It connects the case to earlier cases that share an IP, domain, Reply-To, signer, link or attachment.

The frontend shows all of this across the Dashboard, Cases, the case page tabs and the Campaigns graph. Press **⌘K / Ctrl+K** anywhere to search.

---

## Project layout

```
backend/
  app/main.py          API routes
  app/services/        one file per check (parser, authentication, geo, scoring, …)
  ml/train.py          trains the classifier
  tests/               run with: pytest
  .env.example         every setting, with comments
frontend/
  src/pages/           Dashboard, Analyze, Cases, Case, Campaigns
  src/components/      shared UI pieces
DATASET/               training data (not in git)
```

---

## Common problems

| Problem | Fix |
|---|---|
| `python3: command not found` (Windows) | Use `python` or `py` instead of `python3`. |
| `uvicorn: command not found` | Activate the venv first (`source .venv/bin/activate`). |
| Frontend says **API unreachable** | The backend is not running. Start it on port 8000. |
| `npm install` fails on Vite | Update Node.js to 20.19+ or 22.12+. |
| Map shows no location | Add `IPINFO_TOKEN`, or the sender used Gmail/Outlook, which hide the sender's IP. |
| ML classifier shows *Off* | No model yet. See **ML classifier** above. |
| Port already in use | Stop the other process, or use `--port 8001` and run the frontend with `VITE_API_TARGET=http://127.0.0.1:8001 npm run dev`. |

---

## Run the tests

```bash
cd backend && source .venv/bin/activate && pytest
```
