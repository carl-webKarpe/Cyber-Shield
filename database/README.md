# Cyber-Shield database scripts

Apply these in **MySQL Workbench** against your **MySQL Server 8.0+** instance, in this order:

| Order | File | What it does |
|------:|------|--------------|
| 1 | `../users.sql` | Original Cyber-Shield schema (users, scans, incidents, …). Skip if your database already exists. |
| 2 | `migrations/001_cyber_shield_lab_monitoring.sql` | Adds Super Admin role, lab computers, file events, scan requests/results and the audit log. Safe to re-run; never drops data. |
| 3 | `migrations/002_create_app_user.sql` | Creates the least-privilege `cyber_shield_app` MySQL account used by the web server. Edit the password first. |

See the main `README.md` → *Database setup with MySQL Workbench* for step-by-step screenshots-free instructions.
