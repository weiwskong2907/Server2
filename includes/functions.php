<?php
declare(strict_types=1);

/**
 * Sanitizes and validates input data
 * @param string $data Input data to clean
 * @param bool $strict Enable strict mode for additional filtering
 * @return string Cleaned data
 */
function cleanInput(string $data, bool $strict = false): string {
    $cleaned = trim($data);
    $cleaned = stripslashes($cleaned);
    $cleaned = htmlspecialchars($cleaned, ENT_QUOTES, 'UTF-8');
    
    if ($strict) {
        $cleaned = filter_var($cleaned, FILTER_SANITIZE_STRING);
        $cleaned = preg_replace('/[^A-Za-z0-9\-]/', '', $cleaned);
    }
    
    return $cleaned;
}

/**
 * Generates a cryptographically secure invite code
 * @param int $length Length of the invite code
 * @return string Generated invite code
 * @throws Exception If random_bytes fails
 */
function generateInviteCode(int $length = 16): string {
    try {
        return bin2hex(random_bytes($length));
    } catch (Exception $e) {
        error_log("Failed to generate invite code: " . $e->getMessage());
        throw $e;
    }
}

/**
 * Validates email address
 * @param string $email Email address to validate
 * @return bool True if email is valid
 */
function validateEmail(string $email): bool {
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

/**
 * Validates password strength
 * @param string $password Password to validate
 * @return array Array with validation status and message
 */
function validatePassword(string $password): array {
    $errors = [];
    
    if (strlen($password) < 8) {
        $errors[] = "Password must be at least 8 characters long";
    }
    if (!preg_match('/[A-Z]/', $password)) {
        $errors[] = "Password must contain at least one uppercase letter";
    }
    if (!preg_match('/[a-z]/', $password)) {
        $errors[] = "Password must contain at least one lowercase letter";
    }
    if (!preg_match('/[0-9]/', $password)) {
        $errors[] = "Password must contain at least one number";
    }
    
    return [
        'valid' => empty($errors),
        'errors' => $errors
    ];
}

/**
 * Creates a secure CSRF token
 * @return string Generated CSRF token
 */
function generateCSRFToken(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * Validates CSRF token
 * @param string $token Token to validate
 * @return bool True if token is valid
 */
function validateCSRFToken(string $token): bool {
    return isset($_SESSION['csrf_token']) && 
           hash_equals($_SESSION['csrf_token'], $token);
}

/**
 * Logs an action to the system log
 * @param string $action Action description
 * @param string $severity Log severity level
 * @return void
 */
function logAction(string $action, string $severity = 'info'): void {
    $timestamp = date('Y-m-d H:i:s');
    $user_id = $_SESSION['user_id'] ?? 'guest';
    $log_entry = sprintf("[%s] [%s] User %s: %s\n",
        $timestamp,
        strtoupper($severity),
        $user_id,
        $action
    );
    error_log($log_entry, 3, __DIR__ . '/../logs/system.log');
}

/**
 * Redirects user with a flash message
 * @param string $location Redirect location
 * @param string $message Flash message
 * @param string $type Message type (success/error)
 * @return void
 */
function redirectWithMessage(string $location, string $message, string $type = 'success'): void {
    $_SESSION['flash'] = [
        'message' => $message,
        'type' => $type
    ];
    header("Location: $location");
    exit();
}

/**
 * Sanitizes file name for secure file operations
 * @param string $filename Original filename
 * @return string Sanitized filename
 */
function sanitizeFileName(string $filename): string {
    $info = pathinfo($filename);
    $filename = preg_replace("/[^a-zA-Z0-9]/", "_", $info['filename']);
    return $filename . '.' . $info['extension'];
}

function getUserById($id) {
    // Function to retrieve a user by their ID
    global $pdo; // Assuming $pdo is your PDO connection
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
    $stmt->execute(['id' => $id]);
    return $stmt->fetch();
}

function getAllForums() {
    // Function to retrieve all forums
    global $pdo;
    $stmt = $pdo->query("SELECT * FROM forums");
    return $stmt->fetchAll();
}

function createForum($name, $description) {
    // Function to create a new forum
    global $pdo;
    $stmt = $pdo->prepare("INSERT INTO forums (name, description) VALUES (:name, :description)");
    return $stmt->execute(['name' => $name, 'description' => $description]);
}

function deleteForum($id) {
    global $pdo;
    $stmt = $pdo->prepare("DELETE FROM forums WHERE id = :id");
    return $stmt->execute(['id' => $id]);
}