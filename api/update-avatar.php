<?php
<?php
session_start();
require_once '../config/config.php';
require_once '../includes/auth.php';
require_once '../includes/functions.php';

if (!isLoggedIn()) {
    echo json_encode(['success' => false, 'message' => 'Unauthorized']);
    exit;
}

if (!isset($_FILES['avatar'])) {
    echo json_encode(['success' => false, 'message' => 'No file uploaded']);
    exit;
}

try {
    $file = $_FILES['avatar'];
    $allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
    $maxSize = 5 * 1024 * 1024; // 5MB

    if (!in_array($file['type'], $allowedTypes)) {
        throw new Exception('Invalid file type. Only JPG, PNG and GIF are allowed.');
    }

    if ($file['size'] > $maxSize) {
        throw new Exception('File too large. Maximum size is 5MB.');
    }

    $filename = uniqid('avatar_') . '.' . pathinfo($file['name'], PATHINFO_EXTENSION);
    $uploadPath = '../uploads/avatars/' . $filename;

    if (!move_uploaded_file($file['tmp_name'], $uploadPath)) {
        throw new Exception('Failed to upload file.');
    }

    $avatarUrl = '/uploads/avatars/' . $filename;
    updateUserAvatar($_SESSION['user_id'], $avatarUrl);

    echo json_encode(['success' => true, 'avatar_url' => $avatarUrl]);
} catch (Exception $e) {
    echo json_encode(['success' => false, 'message' => $e->getMessage()]);
}