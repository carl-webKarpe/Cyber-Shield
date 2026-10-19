<?php
/**
 * Cyber-Shield configuration template.
 *
 * Copy this file to config.local.php and fill in your values.
 * config.local.php is ignored by git so secrets never get committed.
 * Every value can also be supplied as an environment variable (shown in brackets).
 */
return [
    // MySQL Server connection (managed with MySQL Workbench)
    'db_host' => '127.0.0.1',          // [DB_HOST]
    'db_port' => 3306,                 // [DB_PORT]
    'db_name' => 'cyber_shield',       // [DB_NAME]
    'db_user' => 'cyber_shield_app',   // [DB_USER]
    'db_password' => '',               // [DB_PASSWORD]

    // VirusTotal API v3 key (https://www.virustotal.com/gui/my-apikey)  [VT_API_KEY]
    'virustotal_api_key' => '',
    // Largest file (bytes) an Admin may upload for a VirusTotal scan. VirusTotal's
    // direct upload limit is 32 MB; PHP's upload_max_filesize must be at least this. [VT_MAX_UPLOAD_BYTES]
    'virustotal_max_upload_bytes' => 32 * 1024 * 1024,
    // VirusTotal API base URL. Only change this to route through an approved proxy. [VT_API_BASE]
    'virustotal_api_base' => 'https://www.virustotal.com/api/v3',

    // Shared secret every Cyber-Shield agent must present to register.
    // Generate one with:  php tools\generate_secret.php   [AGENT_ENROLLMENT_KEY]
    'agent_enrollment_key' => '',
    // When false, newly registered computers stay "Pending approval" until a
    // Super Admin authorizes them in the console.  [AGENT_AUTO_AUTHORIZE]
    'agent_auto_authorize' => false,
    // Seconds between agent heartbeats; a computer is "Offline" after 3 missed beats. [AGENT_HEARTBEAT_SECONDS]
    'agent_heartbeat_seconds' => 30,

    // Allow people to create their own accounts from the sign-in page.
    // Lab deployments should keep this off and create accounts with tools\create_user.php. [ALLOW_REGISTRATION]
    'allow_registration' => false,
];
