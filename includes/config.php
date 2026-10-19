<?php
declare(strict_types=1);

/**
 * Cyber-Shield configuration loader.
 * Reads config.local.php (if present) on top of config.example.php defaults,
 * then lets environment variables override individual values.
 */
function cs_config(string $key)
{
    static $config = null;
    if ($config === null) {
        $root = dirname(__DIR__);
        $config = require $root . '/config.example.php';
        if (is_file($root . '/config.local.php')) {
            $local = require $root . '/config.local.php';
            if (is_array($local)) {
                $config = array_merge($config, $local);
            }
        }
        $env = [
            'db_host' => 'DB_HOST',
            'db_port' => 'DB_PORT',
            'db_name' => 'DB_NAME',
            'db_user' => 'DB_USER',
            'db_password' => 'DB_PASSWORD',
            'virustotal_api_key' => 'VT_API_KEY',
            'virustotal_max_upload_bytes' => 'VT_MAX_UPLOAD_BYTES',
            'virustotal_api_base' => 'VT_API_BASE',
            'agent_enrollment_key' => 'AGENT_ENROLLMENT_KEY',
            'agent_auto_authorize' => 'AGENT_AUTO_AUTHORIZE',
            'agent_heartbeat_seconds' => 'AGENT_HEARTBEAT_SECONDS',
            'allow_registration' => 'ALLOW_REGISTRATION',
        ];
        foreach ($env as $name => $variable) {
            $value = getenv($variable);
            if ($value === false || $value === '') {
                continue;
            }
            if (is_bool($config[$name])) {
                $value = in_array(strtolower($value), ['1', 'true', 'yes', 'on'], true);
            } elseif (is_int($config[$name])) {
                $value = (int) $value;
            }
            $config[$name] = $value;
        }
    }
    return $config[$key] ?? null;
}
