# PatchPilot AI Backend

Initial FastAPI foundation for PatchPilot AI.

## Run

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open:
- http://127.0.0.1:8000
- http://127.0.0.1:8000/docs
- http://127.0.0.1:8000/api/v1/health

## Current milestone

FastAPI foundation only. Next: ZIP upload -> secure extraction -> Semgrep -> normalized vulnerabilities -> API response.
