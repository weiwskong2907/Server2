<?php
declare(strict_types=1);

// Initialize session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

/**
 * Registers a new user
 *
 * @param string $username The username
 * @param string $password The password
 * @param string $email The email address
 * @return bool True on success, false on failure
 */
function register(string $username, string $password, string $email): bool {
    // Include database connection
    require_once '../config/database.php';
    global $pdo;

    // Hash the password
    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

    // Prepare SQL statement
    $stmt = $pdo->prepare("INSERT INTO users (username, password, email) VALUES (?, ?, ?)");
    return $stmt->execute([$username, $hashedPassword, $email]);
}

/**
 * Logs in a user
 *
 * @param string $username The username
 * @param string $password The password
 * @return bool True on success, false on failure
 */
function login(string $username, string $password): bool {
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

/**
 * Checks if user is logged in
 *
 * @return bool True if user is logged in
 */
function isLoggedIn(): bool {
    return isset($_SESSION['user_id']) && !empty($_SESSION['user_id']) &&
           isset($_SESSION['last_activity']) &&
           (time() - $_SESSION['last_activity']) < 1800; // 30 minute timeout
}

/**
 * Checks if logged in user is an admin
 *
 * @return bool True if user is admin
 */
function isAdmin(): bool {
    return isLoggedIn() &&
           isset($_SESSION['role']) &&
           $_SESSION['role'] === 'admin';
}

/**
 * Updates user's last activity timestamp
 *
 * @return void
 */
function updateLastActivity(): void {
    if (isLoggedIn()) {
        $_SESSION['last_activity'] = time();
    }
}

/**
 * Logs out the user
 *
 * @return void
 */
function logout(): void {
    session_unset();
    session_destroy();
}

// Add other authentication related functions here
?>