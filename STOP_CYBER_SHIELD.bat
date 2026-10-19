@echo off
setlocal EnableExtensions EnableDelayedExpansion
title Stop Cyber-Shield Server
cd /d "%~dp0"

rem ======================================================================
rem  Cyber-Shield - STOP_CYBER_SHIELD.bat
rem  Stops only the processes START_CYBER_SHIELD.bat started: the PHP web
rem  server recorded in run\server.pid, and MySQL Server only if Cyber-Shield
rem  was the one that started it.
rem ======================================================================

set "CS_ROOT=%~dp0"
set "CS_RUN=%CS_ROOT%run"
set "CS_LOG=%CS_ROOT%logs\cyber_shield_server.log"
set "CS_MYSQL_SERVICE="
if exist "%CS_ROOT%server_settings.bat" call "%CS_ROOT%server_settings.bat"
if not exist "%CS_ROOT%logs" mkdir "%CS_ROOT%logs"

echo.
echo  [Cyber-Shield] Stopping Cyber-Shield...

if not exist "%CS_RUN%\server.pid" (
    echo  [Cyber-Shield] No running Cyber-Shield web server was recorded.
    goto :mysql
)
set /p CS_PID=<"%CS_RUN%\server.pid"
set "CS_PID=%CS_PID: =%"
rem Only stop the PID if it is still php.exe serving Cyber-Shield's router.php.
powershell -NoProfile -Command "$p = Get-CimInstance Win32_Process -Filter 'ProcessId=%CS_PID%'; if ($p -and $p.Name -eq 'php.exe' -and $p.CommandLine -like '*router.php*') { Stop-Process -Id %CS_PID% -Force; exit 0 } else { exit 2 }"
if errorlevel 2 (
    echo  [Cyber-Shield] PID %CS_PID% is no longer the Cyber-Shield server; nothing to stop.
) else (
    echo  [Cyber-Shield] Web server ^(PID %CS_PID%^) stopped.
    >> "%CS_LOG%" echo [%date% %time%] [Cyber-Shield] Server PID %CS_PID% stopped
)
del "%CS_RUN%\server.pid" >nul 2>&1

:mysql
if exist "%CS_RUN%\mysql_started_by_cyber_shield.flag" (
    if not defined CS_MYSQL_SERVICE (
        for %%S in (MySQL80 MySQL84 MySQL MySQL57) do (
            if not defined CS_MYSQL_SERVICE (
                sc query "%%S" >nul 2>&1
                if not errorlevel 1 set "CS_MYSQL_SERVICE=%%S"
            )
        )
    )
    if defined CS_MYSQL_SERVICE (
        net stop "!CS_MYSQL_SERVICE!" >nul 2>&1
        if errorlevel 1 (
            echo  [Cyber-Shield] Could not stop MySQL service "!CS_MYSQL_SERVICE!" ^(run as administrator^).
        ) else (
            echo  [Cyber-Shield] MySQL service "!CS_MYSQL_SERVICE!" stopped ^(it was started by Cyber-Shield^).
            >> "%CS_LOG%" echo [%date% %time%] [Cyber-Shield] MySQL service !CS_MYSQL_SERVICE! stopped
            del "%CS_RUN%\mysql_started_by_cyber_shield.flag" >nul 2>&1
        )
    )
) else (
    echo  [Cyber-Shield] MySQL Server was already running before Cyber-Shield started; leaving it running.
)

echo.
echo  [Cyber-Shield] Done.
echo.
pause
exit /b 0
