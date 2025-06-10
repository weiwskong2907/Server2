<?php
// Configuration settings for the application

// Site name
define('SITE_NAME', 'Family and Friends Forum');

// Base URL
define('BASE_URL', 'http://localhost/php-forum/');

// Debug mode
define('DEBUG_MODE', true);

// Database settings
define('DB_HOST', 'localhost');
define('DB_NAME', 'php_forum');
define('DB_USER', 'root');
define('DB_PASS', 'myrootpass');

// Upload settings
define('MAX_UPLOAD_SIZE', 5 * 1024 * 1024); // 5MB
define('ALLOWED_IMAGE_TYPES', ['image/jpeg', 'image/png', 'image/gif']);
define('UPLOAD_PATH', __DIR__ . '/../uploads');

// Forum settings
define('ITEMS_PER_PAGE', 20);
define('MAX_TITLE_LENGTH', 100);
define('MIN_POST_LENGTH', 10);
define('MAX_POST_LENGTH', 10000);

// Security settings
define('PASSWORD_MIN_LENGTH', 8);
define('MAX_LOGIN_ATTEMPTS', 5);
define('LOGIN_TIMEOUT', 15 * 60); // 15 minutes

// Cache settings
define('CACHE_ENABLED', true);
define('CACHE_DURATION', 3600); // 1 hour

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