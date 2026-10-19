@echo off
setlocal EnableExtensions
title Stop Cyber-Shield Agent
rem Stops the background Cyber-Shield agent. Add /uninstall to also remove the scheduled task.
net session >nul 2>&1
if errorlevel 1 (
    echo [Cyber-Shield] Please run this file as administrator.
    pause
    exit /b 1
)
powershell -NoProfile -Command "Stop-ScheduledTask -TaskName 'Cyber-Shield Agent' -ErrorAction SilentlyContinue"
echo [Cyber-Shield] Agent stopped. It will start again at the next Windows startup.
if /I "%~1"=="/uninstall" (
    powershell -NoProfile -Command "Unregister-ScheduledTask -TaskName 'Cyber-Shield Agent' -Confirm:$false -ErrorAction SilentlyContinue"
    echo [Cyber-Shield] Scheduled task removed. The agent will no longer start automatically.
)
pause
