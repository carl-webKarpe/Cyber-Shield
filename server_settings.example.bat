@echo off
rem Cyber-Shield server settings. Copy this file to server_settings.bat and edit.
rem START_CYBER_SHIELD.bat and STOP_CYBER_SHIELD.bat read it automatically.

rem Port the dashboard and agents connect to.
set "CS_PORT=8080"

rem Full path to php.exe (leave empty to auto-detect PATH, C:\xampp\php, C:\php).
set "CS_PHP="

rem MySQL Server Windows service name (leave empty to auto-detect MySQL80/MySQL84/MySQL/MySQL57).
set "CS_MYSQL_SERVICE="
