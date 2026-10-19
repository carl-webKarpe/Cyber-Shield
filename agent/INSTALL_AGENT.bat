@echo off
setlocal EnableExtensions
title Install Cyber-Shield Agent
cd /d "%~dp0"

rem ======================================================================
rem  Cyber-Shield Agent installer - run on each lab computer as administrator.
rem  1. Creates a Python virtual environment and installs requirements.
rem  2. Creates config.json from config.example.json (opens it for editing).
rem  3. Tests the connection to the Cyber-Shield server.
rem  4. Restricts this folder to SYSTEM and Administrators (protects the agent secret).
rem  5. Registers the "Cyber-Shield Agent" scheduled task (runs as SYSTEM at startup).
rem ======================================================================

net session >nul 2>&1
if errorlevel 1 (
    echo [Cyber-Shield] Please right-click INSTALL_AGENT.bat and choose "Run as administrator".
    pause
    exit /b 1
)

set "AGENT_DIR=%~dp0"
set "PY="
where py >nul 2>&1 && set "PY=py -3"
if not defined PY (
    where python >nul 2>&1 && set "PY=python"
)
if not defined PY (
    echo [Cyber-Shield] Python 3.10 or newer is required. Install it from python.org
    echo                ^(tick "Add python.exe to PATH"^) and run this installer again.
    pause
    exit /b 1
)
%PY% -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)"
if errorlevel 1 (
    echo [Cyber-Shield] Python 3.10 or newer is required.
    pause
    exit /b 1
)

echo [Cyber-Shield] Creating virtual environment...
if not exist "%AGENT_DIR%.venv\Scripts\python.exe" %PY% -m venv "%AGENT_DIR%.venv"
"%AGENT_DIR%.venv\Scripts\python.exe" -m pip install --disable-pip-version-check -q -r "%AGENT_DIR%requirements.txt"
if errorlevel 1 (
    echo [Cyber-Shield] Installing Python packages failed. Check the internet connection and retry.
    pause
    exit /b 1
)

if not exist "%AGENT_DIR%config.json" (
    copy "%AGENT_DIR%config.example.json" "%AGENT_DIR%config.json" >nul
    echo [Cyber-Shield] Edit config.json: set server_url, enrollment_key and lab_location, then save and close Notepad.
    notepad "%AGENT_DIR%config.json"
)

echo [Cyber-Shield] Testing the connection to the server...
"%AGENT_DIR%.venv\Scripts\python.exe" "%AGENT_DIR%cyber_shield_agent.py" --check
if errorlevel 1 (
    echo [Cyber-Shield] The server could not be reached. Fix config.json or the network, then run this installer again.
    pause
    exit /b 1
)

echo [Cyber-Shield] Restricting folder permissions...
icacls "%AGENT_DIR%." /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" >nul

echo [Cyber-Shield] Registering the Cyber-Shield Agent scheduled task...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$dir = $env:AGENT_DIR.TrimEnd('\');" ^
  "$action = New-ScheduledTaskAction -Execute (Join-Path $dir '.venv\Scripts\pythonw.exe') -Argument ('\"' + (Join-Path $dir 'cyber_shield_agent.py') + '\"') -WorkingDirectory $dir;" ^
  "$trigger = New-ScheduledTaskTrigger -AtStartup;" ^
  "$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest;" ^
  "$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries;" ^
  "Register-ScheduledTask -TaskName 'Cyber-Shield Agent' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Cyber-Shield lab computer monitoring agent' -Force | Out-Null;" ^
  "Start-ScheduledTask -TaskName 'Cyber-Shield Agent'"
if errorlevel 1 (
    echo [Cyber-Shield] Could not register the scheduled task.
    pause
    exit /b 1
)

echo.
echo [Cyber-Shield] Agent installed and started. It starts automatically with Windows.
echo                A Super Admin must now authorize this computer in the Cyber-Shield dashboard
echo                ^(Lab Computers or System Logs page^) before file events are accepted.
echo                Log file: %AGENT_DIR%logs\cyber_shield_agent.log
pause
