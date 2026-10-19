@echo off
setlocal EnableExtensions
title Cyber-Shield Agent (console)
cd /d "%~dp0"
rem Runs the Cyber-Shield agent in this window, for testing. Close the window or press Ctrl+C to stop.
rem For normal use, INSTALL_AGENT.bat runs the agent in the background at startup instead.
set "PYEXE=%~dp0.venv\Scripts\python.exe"
if not exist "%PYEXE%" set "PYEXE=python"
"%PYEXE%" "%~dp0cyber_shield_agent.py" %*
pause
