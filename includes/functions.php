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
 * Checks if user is logged in
 * @return bool True if user is logged in
 */
function isLoggedIn(): bool {
    return isset($_SESSION['user_id']) && !empty($_SESSION['user_id']) && 
           isset($_SESSION['last_activity']) && 
           (time() - $_SESSION['last_activity']) < 1800; // 30 minute timeout
}

/**
 * Checks if logged in user is an admin
 * @return bool True if user is admin
 */
function isAdmin(): bool {
    return isLoggedIn() && 
           isset($_SESSION['role']) && 
           $_SESSION['role'] === 'admin';
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
 * Updates user's last activity timestamp
 * @return void
 */
function updateLastActivity(): void {
    if (isLoggedIn()) {
        $_SESSION['last_activity'] = time();
    }
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

function someFunction() {
    if (condition) {
        // Some code
    } // Make sure each opening brace has a matching closing brace
} // This closing brace might be the extra one

// Check for nested functions that might have extra braces
function outerFunction() {
    function innerFunction() {
        // Code
    } // Make sure nested functions are properly closed
} // And their outer functions too

/**
 * Gets the most recent threads from all forums
 * 
 * @param int $limit Number of threads to return
 * @return array Array of recent threads
 */
function getRecentThreads(int $limit = 5): array {
    global $pdo;
    
    $sql = "SELECT 
                t.id,
                t.title,
                t.created_at,
                u.username as author,
                f.name as forum_name,
                (SELECT COUNT(*) FROM posts p WHERE p.thread_id = t.id) as reply_count
            FROM threads t
            JOIN users u ON t.user_id = u.id
            JOIN forums f ON t.forum_id = f.id
            WHERE t.deleted_at IS NULL
            ORDER BY t.created_at DESC
            LIMIT :limit";
            
    try {
        $stmt = $pdo->prepare($sql);
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->execute();
        
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        logError('Error getting recent threads: ' . $e->getMessage());
        return [];
    }
}

/**
 * Gets active users with their latest activity
 * 
 * @param int $limit Number of users to return
 * @return array Array of active users
 */
function getActiveUsers(int $limit = 10): array {
    global $pdo;
    
    $sql = "SELECT 
                u.id,
                u.username,
                u.last_seen,
                u.avatar_url,
                COUNT(DISTINCT t.id) as thread_count,
                COUNT(DISTINCT p.id) as post_count
            FROM users u
            LEFT JOIN threads t ON u.id = t.user_id AND t.deleted_at IS NULL
            LEFT JOIN posts p ON u.id = p.user_id AND p.deleted_at IS NULL
            WHERE u.active = 1
            GROUP BY u.id
            ORDER BY u.last_seen DESC
            LIMIT :limit";
            
    try {
        $stmt = $pdo->prepare($sql);
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->execute();
        
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        logError('Error getting active users: ' . $e->getMessage());
        return [];
    }
}