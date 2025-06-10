<?php
session_start();

function register($username, $password, $email) {
    // Include database connection
    require_once '../config/database.php';
    global $pdo;

    // Hash the password
    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

    // Prepare SQL statement
    $stmt = $pdo->prepare("INSERT INTO users (username, password, email) VALUES (?, ?, ?)");
    return $stmt->execute([$username, $hashedPassword, $email]);
}

function login($username, $password) {
    // Include database connection
    require_once '../config/database.php';
    global $pdo;

    // Prepare SQL statement
    $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->execute([$username]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    // Verify password
    if ($user && password_verify($password, $user['password'])) {
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        return true;
    }
    return false;
}

function isLoggedIn() {
    return isset($_SESSION['user_id']);
}

function logout() {
    session_unset();
    session_destroy();
}
?>