# Run and Push Supply Chain Guardian

## Prerequisites

- Windows PowerShell
- Python 3.11 or newer
- Git
- GitHub account

## First-time setup

Open PowerShell in the project folder:

```powershell
cd "C:\Users\avina\OneDrive\Documents\GitHub\Supply-Chain-Guardian"
python -m pip install -r requirements.txt
```

Sign in to GitHub in VS Code:

1. Open the **Accounts** menu in the bottom-left of VS Code.
2. Select **Sign in with GitHub**.
3. Complete the browser sign-in.

## Run the web application

```powershell
cd "C:\Users\avina\OneDrive\Documents\GitHub\Supply-Chain-Guardian"
.\run_app.ps1
```

If PowerShell blocks the script:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\run_app.ps1
```

Open [http://127.0.0.1:8765](http://127.0.0.1:8765) in a browser.

Alternatively, start it directly:

```powershell
python -m guardian serve --port 8765
```

## Stop the server

Press `Ctrl+C` in the PowerShell terminal running the server.

## Save and push changes

From the project folder:

```powershell
git add .
git status
git diff --cached --stat
git commit -m "Improve Suspicious Changes UI"
git push origin main
```

If you have not configured an identity yet:

```powershell
git config --global user.name "Your Name"
git config --global user.email "you@example.com"
```

To update from GitHub first:

```powershell
git pull --rebase origin main
git push origin main
```

## Useful verification commands

```powershell
python -m pytest tests/test_llm_server_pipeline.py -q
Invoke-WebRequest -Uri "http://127.0.0.1:8765" -UseBasicParsing
git --no-pager status
git --no-pager log -3 --oneline
```
