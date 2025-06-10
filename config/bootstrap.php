<?php
// Prevent direct access
if (!defined('BASE_PATH')) {
    define('BASE_PATH', dirname(__DIR__));
}

// Load configurations before any session starts
require_once __DIR__ . '/config.php';

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

// Configure error handling
error_reporting(E_ALL);
ini_set('display_errors', DEBUG_MODE ? '1' : '0');
ini_set('log_errors', '1');
ini_set('error_log', $logFile);

// Configure session settings before starting session
if (session_status() === PHP_SESSION_NONE) {
    // Session configuration
    ini_set('session.cookie_httponly', '1');
    ini_set('session.use_only_cookies', '1');
    ini_set('session.cookie_secure', '1');
    ini_set('session.cookie_samesite', 'Strict');
    ini_set('session.gc_maxlifetime', 1800);
    
    // Start session
    session_start();
}

// Load remaining configurations
require_once BASE_PATH . '/includes/functions.php';
require_once BASE_PATH . '/includes/auth.php';

// Set default timezone
date_default_timezone_set('UTC');

// Initialize database connection
require_once BASE_PATH . '/config/database.php';

// Security headers
if (!headers_sent()) {
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: SAMEORIGIN');
    header('X-XSS-Protection: 1; mode=block');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    }
}

// Example usage in other files
require_once __DIR__ . '/../config/bootstrap.php';
session_start();
// ...rest of the code...