<?php
// Load configuration in the correct order
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/php_settings.php';

// Create necessary directories if they don't exist
$directories = [
    __DIR__ . '/../logs',
    __DIR__ . '/../uploads',
    __DIR__ . '/../uploads/avatars',
    __DIR__ . '/../cache'
];

foreach ($directories as $dir) {
    if (!file_exists($dir)) {
        mkdir($dir, 0755, true);
    }
}

// Initialize error logging
if (!file_exists(__DIR__ . '/../logs/system.log')) {
    touch(__DIR__ . '/../logs/system.log');
    chmod(__DIR__ . '/../logs/system.log', 0644);
}

// Example usage in other files
require_once __DIR__ . '/../config/bootstrap.php';
session_start();
// ...rest of the code...