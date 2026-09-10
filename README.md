# SCC Vulnerability Intelligence Demo

## Run The Dashboard

```powershell
docker compose up --build dashboard
```

Open `http://127.0.0.1:5000`.

## One-Command Demo Startup

From PowerShell at the repository root:

```powershell
.\demo.ps1
```

This starts both Docker services, seeds the presentation CVE, checks both URLs, and opens them in the browser. Add `-CollectLive` to run the live NVD and GitHub collector too, or `-NoBrowser` to keep the browser closed.

## Collect Live Data

From the terminal:

```powershell
npm.cmd run get-cves
```

From the dashboard, use `Collect latest`. It runs a one-day NVD CVE and GitHub commit collection.

## Optional Daily Collection

```powershell
docker compose --profile scheduler up --build
```

## AI Commit Check

Create `.env` from `.env.example` and set a fresh `OPENAI_API_KEY`.

Install the pre-push hook:

```powershell
npm.cmd run install-hooks
```

Commit through the checker:

```powershell
npm.cmd run gitcommit -- "fix sql injection in login"
```

For intentionally risky demo commits:

```powershell
npm.cmd run gitcommit -- "add intentionally vulnerable login" --allow-risk
```

For an intentional risky push:

```powershell
$env:ALLOW_RISKY_PUSH="1"
git push
```

## Demo Vulnerable App Repo

The demo app scaffold is in `vulnerable-app/`. To publish it as a separate GitHub repo:

```powershell
cd vulnerable-app
git init
git add .
git commit -m "add intentionally vulnerable flask demo app"
git branch -M main
git remote add origin https://github.com/threelayers/scc-vulnerable-demo-app.git
git push -u origin main
```

Create the public repo on GitHub first if it does not exist.
