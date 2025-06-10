<?php
// Configuration settings for the application

// Site name
define('SITE_NAME', 'Family and Friends Forum');

// Base URL
define('BASE_URL', 'http://localhost/php-forum/');

// Debug mode
define('DEBUG_MODE', true);

// Database settings
define('DB_HOST', 'mysql-db');
define('DB_NAME', 'php_forum'); // Update with your database name
define('DB_USER', 'root');
define('DB_PASS', 'myrootpass'); // Update with your database password

// Set timezone
date_default_timezone_set('UTC');

// Configure error logging
ini_set('log_errors', '1');
ini_set('error_log', __DIR__ . '/../logs/system.log');

// Session security settings
ini_set('session.cookie_httponly', '1');
ini_set('session.use_only_cookies', '1');
ini_set('session.cookie_secure', '1');
ini_set('session.cookie_samesite', 'Strict');

// Other constants can be added here as needed
?>