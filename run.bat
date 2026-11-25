@echo off
REM GQLProbe launcher for Windows — setup, probe, test, doctor,
REM lab, menu. Pure Python; requests is preferred, urllib is the
REM fallback, so the probe works with nothing installed.
REM Usage:
REM   run.bat setup
REM   run.bat probe http://127.0.0.1:4000/graphql --token lab-token-alice
REM   run.bat test
REM   run.bat doctor
REM   run.bat lab vulnerable
REM   run.bat menu
setlocal
cd /d "%~dp0"
if "%1"=="" (
    python run.py
    exit /b %ERRORLEVEL%
)
python run.py %*
exit /b %ERRORLEVEL%
