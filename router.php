<?php
/**
 * Cyber-Shield router for PHP's built-in web server (used by START_CYBER_SHIELD.bat).
 * Blocks private folders and files that Apache would protect with .htaccess.
 */
$path = rawurldecode(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?? '/');
$path = '/' . ltrim(str_replace('\\', '/', $path), '/');

$blocked = '#^/(\.|includes/|database/|agent/|tools/|storage/|logs/|run/)|^/(config\.local\.php|config\.example\.php|router\.php)$|\.(sql|bat|md|log|json|ps1)$#i';
if (preg_match($blocked, $path) || strpos($path, '..') !== false) {
    http_response_code(404);
    echo 'Not found';
    return true;
}
if ($path === '/') {
    $_SERVER['SCRIPT_NAME'] = '/index.php';
    require __DIR__ . '/index.php';
    return true;
}
return false;
