@echo off
setlocal EnableExtensions EnableDelayedExpansion
title Cyber-Shield Server
cd /d "%~dp0"

rem ======================================================================
rem  Cyber-Shield - START_CYBER_SHIELD.bat
rem  Starts the Cyber-Shield web server (PHP), checks MySQL Server and the
rem  database, and shows the address lab computers and browsers should use.
rem  Optional overrides live in server_settings.bat (see server_settings.example.bat).
rem ======================================================================

set "CS_ROOT=%~dp0"
set "CS_RUN=%CS_ROOT%run"
set "CS_LOG=%CS_ROOT%logs\cyber_shield_server.log"
set "CS_PORT=8080"
set "CS_PHP="
set "CS_MYSQL_SERVICE="
if exist "%CS_ROOT%server_settings.bat" call "%CS_ROOT%server_settings.bat"
if not exist "%CS_RUN%" mkdir "%CS_RUN%"
if not exist "%CS_ROOT%logs" mkdir "%CS_ROOT%logs"

echo.
echo  =====================================================
echo     Cyber-Shield  ^|  Lab Security Monitoring Server
echo  =====================================================
echo.
call :log "Start requested"

net session >nul 2>&1
if errorlevel 1 (set "CS_IS_ADMIN=0") else (set "CS_IS_ADMIN=1")

rem ---- 1. Locate PHP ---------------------------------------------------
if not defined CS_PHP (
    for %%P in (php.exe) do if not "%%~$PATH:P"=="" set "CS_PHP=%%~$PATH:P"
)
if not defined CS_PHP if exist "C:\xampp\php\php.exe" set "CS_PHP=C:\xampp\php\php.exe"
if not defined CS_PHP if exist "C:\php\php.exe" set "CS_PHP=C:\php\php.exe"
if not defined CS_PHP (
    echo  [Cyber-Shield] ERROR: PHP was not found.
    echo                Install PHP 8.1+ or XAMPP, or set CS_PHP in server_settings.bat.
    call :log "PHP not found"
    goto :fail
)
echo  [Cyber-Shield] PHP: %CS_PHP%

rem ---- 2. Already running? ---------------------------------------------
if exist "%CS_RUN%\server.pid" (
    set /p CS_OLD_PID=<"%CS_RUN%\server.pid"
    tasklist /FI "PID eq !CS_OLD_PID!" /FI "IMAGENAME eq php.exe" 2>nul | find /I "php.exe" >nul
    if not errorlevel 1 (
        echo  [Cyber-Shield] The server is already running ^(PID !CS_OLD_PID!^).
        goto :show_addresses
    )
    del "%CS_RUN%\server.pid" >nul 2>&1
)

rem ---- 3. MySQL Server service -----------------------------------------
if not defined CS_MYSQL_SERVICE (
    for %%S in (MySQL80 MySQL84 MySQL MySQL57) do (
        if not defined CS_MYSQL_SERVICE (
            sc query "%%S" >nul 2>&1
            if not errorlevel 1 set "CS_MYSQL_SERVICE=%%S"
        )
    )
)
if defined CS_MYSQL_SERVICE (
    sc query "%CS_MYSQL_SERVICE%" | find "RUNNING" >nul
    if errorlevel 1 (
        echo  [Cyber-Shield] Starting MySQL Server service "%CS_MYSQL_SERVICE%"...
        net start "%CS_MYSQL_SERVICE%" >nul 2>&1
        if errorlevel 1 (
            echo  [Cyber-Shield] Could not start "%CS_MYSQL_SERVICE%". Right-click this file and choose
            echo                "Run as administrator", or start MySQL from MySQL Workbench / services.msc.
            call :log "MySQL service %CS_MYSQL_SERVICE% could not be started"
            goto :fail
        )
        echo started> "%CS_RUN%\mysql_started_by_cyber_shield.flag"
        call :log "Started MySQL service %CS_MYSQL_SERVICE%"
    ) else (
        echo  [Cyber-Shield] MySQL Server service "%CS_MYSQL_SERVICE%" is running.
    )
) else (
    echo  [Cyber-Shield] No MySQL Windows service found ^(MySQL80/MySQL84/MySQL/MySQL57^).
    echo                Assuming MySQL Server is already running; set CS_MYSQL_SERVICE to override.
)

rem ---- 4. Database connectivity ------------------------------------------
if not exist "%CS_ROOT%config.local.php" (
    echo  [Cyber-Shield] ERROR: config.local.php is missing. Copy config.example.php to
    echo                config.local.php and fill in the database and VirusTotal settings.
    call :log "config.local.php missing"
    goto :fail
)
"%CS_PHP%" "%CS_ROOT%tools\check_db.php"
if errorlevel 1 (
    call :log "Database check failed"
    goto :fail
)

rem ---- 5. Windows Firewall ------------------------------------------------
set "CS_RULE=Cyber-Shield Server (TCP %CS_PORT%)"
netsh advfirewall firewall show rule name="%CS_RULE%" >nul 2>&1
if errorlevel 1 (
    if "%CS_IS_ADMIN%"=="1" (
        netsh advfirewall firewall add rule name="%CS_RULE%" dir=in action=allow protocol=TCP localport=%CS_PORT% profile=private,domain >nul
        echo  [Cyber-Shield] Firewall rule added for TCP port %CS_PORT% ^(Private/Domain networks^).
        call :log "Firewall rule added for port %CS_PORT%"
    ) else (
        echo  [Cyber-Shield] NOTE: no firewall rule for port %CS_PORT%. Run this file once as
        echo                administrator so lab computers can reach the server.
    )
)

rem ---- 6. Start the PHP web server ----------------------------------------
set "CS_SERVER_PID="
for /f "usebackq delims=" %%I in (`powershell -NoProfile -ExecutionPolicy Bypass -Command "$p = Start-Process -FilePath $env:CS_PHP -ArgumentList '-d','upload_max_filesize=40M','-d','post_max_size=48M','-d','max_execution_time=300','-d','log_errors=1','-d','error_log=logs\php_errors.log','-S','0.0.0.0:%CS_PORT%','-t','.','router.php' -WorkingDirectory $env:CS_ROOT -WindowStyle Minimized -PassThru; $p.Id"`) do set "CS_SERVER_PID=%%I"
if not defined CS_SERVER_PID (
    echo  [Cyber-Shield] ERROR: the PHP web server could not be started.
    call :log "PHP server failed to start"
    goto :fail
)
> "%CS_RUN%\server.pid" echo %CS_SERVER_PID%
timeout /t 2 /nobreak >nul
powershell -NoProfile -Command "try { $r = Invoke-WebRequest -UseBasicParsing -TimeoutSec 10 'http://127.0.0.1:%CS_PORT%/login.php'; exit [int]($r.StatusCode -ne 200) } catch { exit 1 }"
if errorlevel 1 (
    echo  [Cyber-Shield] ERROR: the server did not answer on port %CS_PORT%. Is the port already in use?
    call :log "Server did not answer on port %CS_PORT%"
    taskkill /PID %CS_SERVER_PID% /F >nul 2>&1
    del "%CS_RUN%\server.pid" >nul 2>&1
    goto :fail
)
echo  [Cyber-Shield] Web server running ^(PID %CS_SERVER_PID%^) on port %CS_PORT%.
call :log "Server started, PID %CS_SERVER_PID%, port %CS_PORT%"

:show_addresses
echo.
echo  Open the dashboard from this computer:   http://localhost:%CS_PORT%/
echo.
echo  Lab computers and other browsers use one of these addresses
echo  (put the Ethernet/LAN address in each agent's config.json "server_url"):
powershell -NoProfile -Command "Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } | Sort-Object { $_.InterfaceAlias -notmatch 'Ethernet' } | ForEach-Object { $kind = if ($_.InterfaceAlias -match 'Wi-?Fi|Wireless|WLAN') { 'Wi-Fi / hotspot' } elseif ($_.InterfaceAlias -match 'Ethernet') { 'Ethernet LAN - recommended' } else { 'other' }; '    http://{0}:%CS_PORT%/    [{1}: {2}]' -f $_.IPAddress, $_.InterfaceAlias, $kind }"
echo.
echo  To stop Cyber-Shield, run STOP_CYBER_SHIELD.bat.
echo.
start "" "http://localhost:%CS_PORT%/login.php"
pause
exit /b 0

:fail
echo.
echo  [Cyber-Shield] Startup did not complete. Details: logs\cyber_shield_server.log
echo.
pause
exit /b 1

:log
>> "%CS_LOG%" echo [%date% %time%] [Cyber-Shield] %~1
exit /b 0
