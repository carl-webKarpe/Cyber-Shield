<?php
declare(strict_types=1);

/**
 * Cyber-Shield bootstrap: loads configuration, the database connection and shared helpers.
 * Provides $pdo to the including script.
 */
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/session.php';
require_once __DIR__ . '/audit.php';
require_once dirname(__DIR__) . '/db.php';

const CS_APP_NAME = 'Cyber-Shield';
const CS_VERSION = '4.0.0';
