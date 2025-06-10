<?php
session_start();
define('BASE_PATH', __DIR__);
require_once __DIR__ . '/config/bootstrap.php';

try {
    // Your main application code here
    include __DIR__ . '/includes/header.php';
    include __DIR__ . '/pages/home.php';
    include __DIR__ . '/includes/footer.php';
} catch (Throwable $e) {
    if (DEBUG_MODE) {
        echo '<pre>' . htmlspecialchars($e->getMessage()) . '</pre>';
    } else {
        error_log($e->getMessage());
        include __DIR__ . '/pages/error.php';
    }
}