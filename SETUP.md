# Cyber-Shield Setup Guide

This guide covers setting up the Cyber-Shield server on Windows, starting and stopping it, and connecting the lab computers.
Do the steps in order. For background on features and security, see `README.md`.

---

## Part 1 — One-time server setup

### Step 1. Install the required software

Install these on the **server computer**:

| Software | Where to get it | Notes |
|---|---|---|
| **MySQL Server 8.0+** and **MySQL Workbench** | MySQL Installer for Windows (dev.mysql.com/downloads/installer) | Installs both. Remember the `root` password you set. The service is usually named `MySQL80`. |
| **PHP 8.1+** | XAMPP (apachefriends.org) or windows.php.net | XAMPP's PHP (`C:\xampp\php\php.exe`) is found automatically. Do **not** start XAMPP's MySQL/MariaDB; Cyber-Shield uses MySQL Server. |
| **Git** | git-scm.com | Used to download the project. |
| **VirusTotal API key** | virustotal.com → sign in → profile → **API key** | Free key: 4 requests/minute, 500/day. |

**Check the PHP extensions:** open `php.ini` (for XAMPP: `C:\xampp\php\php.ini`). Make sure these lines have **no `;`** at the start:

```ini
extension=curl
extension=pdo_mysql
extension=mbstring
extension=fileinfo
```

### Step 2. Download the project

Open **Command Prompt** and run:

```bat
cd C:\
git clone -b claude/adoring-planck-jad4is https://github.com/carl-webkarpe/cyber-shield.git Cyber-Shield
cd C:\Cyber-Shield
```

Already have the project? Back up any local changes first, then update:

```bat
cd C:\Cyber-Shield
git stash push -u -m "backup before upgrade"
git fetch origin
git checkout claude/adoring-planck-jad4is
git pull origin claude/adoring-planck-jad4is
```

### Step 3. Create the database in MySQL Workbench

1. Open **MySQL Workbench** and click your local connection (`root`).
2. **If you already have a `cyber_shield` database, back it up first:**
   *Server → Data Export* → tick `cyber_shield` → *Export to Self-Contained File* → **Start Export**.
3. **New install only:** *File → Open SQL Script…* → `C:\Cyber-Shield\users.sql` → click the ⚡ **Execute** button.
4. *File → Open SQL Script…* → `C:\Cyber-Shield\database\migrations\001_cyber_shield_lab_monitoring.sql` → ⚡ **Execute**.
   This only adds tables and columns, so it is safe to run again.
5. *File → Open SQL Script…* → `C:\Cyber-Shield\database\migrations\002_create_app_user.sql`.
   Replace `CHANGE_ME_STRONG_PASSWORD` with a strong password of your own and write it down. Then ⚡ **Execute**.
6. In the *Schemas* panel, right-click → **Refresh All**. Under `cyber_shield` → *Tables* you should see
   `lab_computers`, `file_events`, `scan_requests`, `scan_results` and `audit_logs`.

### Step 4. Configure Cyber-Shield

In Command Prompt (inside `C:\Cyber-Shield`):

```bat
copy config.example.php config.local.php
php tools\generate_secret.php
```

Copy the long value that `generate_secret.php` prints. This is your **agent enrollment key**.

```bat
notepad config.local.php
```

Change these lines and save:

```php
'db_user' => 'cyber_shield_app',
'db_password' => 'THE PASSWORD FROM STEP 3.5',
'virustotal_api_key' => 'YOUR VIRUSTOTAL API KEY',
'agent_enrollment_key' => 'THE VALUE FROM generate_secret.php',
```

> If `php` is not recognized, use the full path, for example `C:\xampp\php\php.exe tools\generate_secret.php`.

**Optional:** to change the port (default `8080`), the PHP path or the MySQL service name:

```bat
copy server_settings.example.bat server_settings.bat
notepad server_settings.bat
```

### Step 5. Create the user accounts

Create at least one Super Admin and one Admin. Each command asks for a password; it is not shown while you type.

```bat
php tools\create_user.php --email=superadmin@lab.local --name="IT Head" --role=superadmin
php tools\create_user.php --email=admin@lab.local --name="Lab Admin" --role=admin
```

| Role | Can do |
|---|---|
| **Super Admin** | Monitor lab computers, view file activity, read System Logs, authorize lab computers. **No scanning.** |
| **Admin** | Monitor lab computers, scan files and URLs with VirusTotal, view scan results and history. |

Other account commands:

```bat
php tools\create_user.php --email=admin@lab.local --role=admin        (reset password; keep the same --role)
php tools\create_user.php --email=former@lab.local --disable          (disable account)
```

---

## Part 2 — Starting and stopping the server

### Start the server

1. Open the `C:\Cyber-Shield` folder.
2. **The first time:** right-click **`START_CYBER_SHIELD.bat`** → **Run as administrator**.
   This lets it add the Windows Firewall rule and start MySQL if it is stopped.
   Later you can simply double-click it.
3. The window checks each step and should end like this:

   ```
   [Cyber-Shield] PHP: C:\xampp\php\php.exe
   [Cyber-Shield] MySQL Server service "MySQL80" is running.
   [Cyber-Shield] Connected to MySQL Server 8.0.xx (database cyber_shield)
   [Cyber-Shield] Web server running (PID 1234) on port 8080.

    Open the dashboard from this computer:   http://localhost:8080/

    Lab computers and other browsers use one of these addresses
       http://192.168.1.10:8080/    [Ethernet: Ethernet LAN - recommended]
   ```

4. The sign-in page opens in your browser. Sign in with an account from Step 5.
5. **Write down the Ethernet address** (for example `http://192.168.1.10:8080`). The lab computers need it in Part 3.

Keep the minimized **php.exe** window open; closing it stops the server.

### Stop the server

Double-click **`STOP_CYBER_SHIELD.bat`**.

* It stops only the web server that `START_CYBER_SHIELD.bat` started.
* It stops MySQL **only if** `START_CYBER_SHIELD.bat` was the one that started it.

### Every day

| To do | Action |
|---|---|
| Start Cyber-Shield | Double-click `START_CYBER_SHIELD.bat` |
| Open the dashboard | `http://localhost:8080/` on the server, or `http://<server-ip>:8080/` from another PC |
| Stop Cyber-Shield | Double-click `STOP_CYBER_SHIELD.bat` |
| Startup log | `logs\cyber_shield_server.log` |
| Activity and audit log | `logs\cyber_shield.log`, or **System Logs** in the dashboard (Super Admin) |

> **Tip:** give the server a fixed IP address (a static IP or a DHCP reservation on the router). Then the address in the agents never changes.

---

## Part 3 — Connecting the lab computers

Do this on **each lab computer**.

1. Install **Python 3.10 or newer** from python.org.
   In the installer tick **"Add python.exe to PATH"** and choose **"Install for all users"** (under *Customize installation*).
2. Copy the `agent` folder from the server to the lab computer, for example to `C:\CyberShieldAgent`.
3. Right-click **`INSTALL_AGENT.bat`** → **Run as administrator**.
4. When Notepad opens `config.json`, change these values, then **save and close Notepad**:

   ```json
   "server_url": "http://192.168.1.10:8080",
   "enrollment_key": "THE SAME agent_enrollment_key AS IN config.local.php",
   "lab_location": "Computer Lab 1",
   ```

   By default the agent watches the Downloads, Desktop and Documents folders of every user (`C:\Users\*\...`).
5. The installer tests the connection. You should see three **[OK]** lines. It then starts the agent, and the agent starts automatically with Windows from then on.
6. On the server, sign in as **Super Admin** → **Lab Computers** → click **Authorize** next to the new computer.
   Until you do this, the computer shows **Pending approval** and its file events are refused.

Agent commands (in the agent folder):

| File | What it does |
|---|---|
| `START_AGENT.bat --check` | Tests the connection to the server and exits |
| `START_AGENT.bat` | Runs the agent in a window (for testing) |
| `STOP_AGENT.bat` (as admin) | Stops the background agent |
| `STOP_AGENT.bat /uninstall` (as admin) | Stops it and removes it from Windows startup |
| `logs\cyber_shield_agent.log` | Agent log file |

### Network options

| Connection | Use |
|---|---|
| **Ethernet / LAN cable** | **Recommended.** The most reliable option. |
| Same Wi-Fi network | Works if the router allows devices to talk to each other. Some routers block this ("AP/client isolation"). |
| Mobile hotspot | Works for testing. The server IP usually changes each time, so update `server_url`. |

---

## Part 4 — Check that everything works

1. Sign in as **Super Admin**. The lab computer should be listed under **Lab Computers** as **Online**.
2. On the lab computer, save any file into its Downloads folder.
3. Within about 10 seconds the file should appear under **File Activity**.
4. Sign in as **Admin** → **File Activity** → click **Scan** on that file. The VirusTotal result appears below the table.
   * **No detections / risk level** → VirusTotal knows the file.
   * **Not in VirusTotal / Not scanned** → VirusTotal has never seen it. Click **Upload file from lab computer to VirusTotal** to have it analysed. Do not upload personal or confidential files.
5. As **Admin**, open **Cyber Scanner** and upload a test file to check the direct upload scan.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `PHP was not found` | Install PHP or XAMPP, or set `CS_PHP` in `server_settings.bat` (for example `set "CS_PHP=C:\xampp\php\php.exe"`). |
| `config.local.php is missing` | Do Part 1, Step 4. |
| `Database connection FAILED` | Check that the MySQL80 service is running (MySQL Workbench → *Server → Startup/Shutdown*) and that `db_user` / `db_password` match Step 3.5. |
| `Missing tables: ...` | Run migration `001_cyber_shield_lab_monitoring.sql` again in MySQL Workbench. |
| `Could not start "MySQL80"` | Run `START_CYBER_SHIELD.bat` as administrator, or start MySQL from MySQL Workbench. |
| `The server did not answer on port 8080` | Another program uses port 8080. Set another port with `CS_PORT` in `server_settings.bat`, and update every agent's `server_url`. |
| Lab computer `[FAIL] Cannot open TCP port` | Check that the server is running and both PCs are on the same network. On the server, open *Settings → Network & Internet* and set the network profile to **Private**. Run `START_CYBER_SHIELD.bat` as administrator once to add the firewall rule. |
| `Invalid enrollment key` | `enrollment_key` in the agent's `config.json` must exactly match `agent_enrollment_key` in `config.local.php`. |
| `Request timestamp is outside the allowed window` | The lab computer's clock is wrong. Turn on *Set time automatically* in Windows. |
| Computer stays **Pending approval** | A Super Admin must click **Authorize** under **Lab Computers**. |
| `VirusTotal is not configured` | Add `virustotal_api_key` to `config.local.php`. |
| `VirusTotal rate limit reached` | The free key allows 4 requests per minute. Wait a minute and try again. |
| `Too many failed sign-in attempts` | Wait 15 minutes, or reset the password with `tools\create_user.php`. |
| Cannot sign in as `analyst@cybershield.local` | This old demo account is disabled for security. Create accounts with `tools\create_user.php`. |
