<?php
// Prevent direct access
if (!defined('BASE_PATH')) {
    define('BASE_PATH', dirname(__DIR__));
}

require_once __DIR__ . '/config.php';

// Configure error handling
error_reporting(E_ALL);
ini_set('display_errors', DEBUG_MODE ? '1' : '0');
ini_set('log_errors', '1');
ini_set('error_log', BASE_PATH . '/logs/system.log');

// Create necessary directories
$directories = [
    BASE_PATH . '/logs',
    BASE_PATH . '/uploads',
    BASE_PATH . '/uploads/avatars',
    BASE_PATH . '/cache'
];

foreach ($directories as $dir) {
    if (!file_exists($dir)) {
        mkdir($dir, 0755, true);
    }
}

// Initialize error logging
$logFile = BASE_PATH . '/logs/system.log';
if (!file_exists($logFile)) {
    touch($logFile);
    chmod($logFile, 0644);
}

// Configure session settings before starting session
if (session_status() === PHP_SESSION_NONE) {
    // Session configuration
    ini_set('session.cookie_httponly', '1');
    ini_set('session.use_only_cookies', '1');
    ini_set('session.cookie_secure', '1');
    ini_set('session.cookie_samesite', 'Strict');
    ini_set('session.gc_maxlifetime', 1800);
    
    session_start();
}

// Load core files
require_once BASE_PATH . '/includes/functions.php';
require_once BASE_PATH . '/includes/auth.php';
require_once BASE_PATH . '/config/database.php';