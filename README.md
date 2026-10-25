# AI Mobile Shield Enterprise

A development-stage security monitoring dashboard with a FastAPI backend, SQLite event storage, and a simple repeated-failed-login detector. **Security events and detection are simulated/demo functionality; this is not yet a deployed protection agent for phones, computers, email, websites, or networks.**

## Requirements
- Python 3.11+ recommended
- Windows PowerShell (commands below)

## Install
```powershell
cd AI-Mobile-Shield-Enterprise
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Run
```powershell
python -m uvicorn app.main:app --host 127.0.0.1 --port 8010 --reload
```
Open the dashboard at http://127.0.0.1:8010/dashboard and API docs at http://127.0.0.1:8010/docs.

## Test
Open a second PowerShell window in the project folder, activate the environment, then run:
```powershell
.\.venv\Scripts\Activate.ps1
python -m pytest -q
```

## Demo failed-login detection
Send five POST requests to `/api/v1/events` with `event_type` set to `failed_login` (same `asset_id` and `source`) to trigger a high-severity demo alert. All demo events are marked `simulated: true`.

## Current scope and limitations
- Stores events in a local SQLite database.
- Provides health and event-list APIs.
- Flags repeated failed logins in the running process. The detector state is in memory and resets when the server restarts.
- Does not automatically inspect device activity, email, network traffic, or external websites. Those integrations require separate agents, permissions, and secure deployment.
