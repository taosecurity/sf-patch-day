@echo off
rem sf-patch-day launcher: runs the tool with the Python on PATH (3.9 or newer). Arguments pass through.
where python >nul 2>nul
if errorlevel 1 (
  echo RESULT: CANNOT CHECK: Python wasn't found. Fix: install Python 3.9 or newer from https://www.python.org and tick "Add python.exe to PATH".
  exit /b 3
)
python -I "%~dp0sf-patch-day.py" %*
exit /b %errorlevel%
