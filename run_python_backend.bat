@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Creating Python virtual environment...
  py -m venv .venv
)
call ".venv\Scripts\activate.bat"
python -m pip install -r python_backend\requirements.txt
uvicorn python_backend.main:app --host 127.0.0.1 --port 3000 --reload
