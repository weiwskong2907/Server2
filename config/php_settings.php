<?php
// PHP Settings Configuration
// This file must be included before any session starts

// Session security settings
ini_set('session.cookie_httponly', '1');
ini_set('session.use_only_cookies', '1');
ini_set('session.cookie_secure', '1');
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.gc_maxlifetime', 1800); // 30 minutes
ini_set('session.gc_probability', 1);
ini_set('session.gc_divisor', 100);

// Error reporting settings
ini_set('log_errors', '1');
ini_set('error_log', __DIR__ . '/../logs/system.log');
error_reporting(E_ALL);
ini_set('display_errors', DEBUG_MODE ? '1' : '0');

// Timezone setting
date_default_timezone_set('UTC');