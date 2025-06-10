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














































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































}    }        $stmt->execute(['role_id' => $role_id, 'permission_id' => $permission_id]);        $stmt = $pdo->prepare("INSERT INTO role_permissions (role_id, permission_id) VALUES (:role_id, :permission_id)");    foreach ($permission_ids as $permission_id) {        $stmt->execute(['role_id' => $role_id]);    $stmt = $pdo->prepare("DELETE FROM role_permissions WHERE role_id = :role_id");    global $pdo;    // Function to set permissions for a rolefunction setRolePermissions($role_id, $permission_ids) {}    return $stmt->fetchAll();    $stmt->execute(['role_id' => $role_id]);    ");        WHERE permissions.role_id = :role_id        FROM role_permissions as permissions        SELECT permissions.*    $stmt = $pdo->prepare("    global $pdo;    // Function to get permissions for a specific rolefunction getRolePermissions($role_id) {}    return $stmt->fetchAll();    $stmt = $pdo->query("SELECT * FROM permissions");    global $pdo;    // Function to retrieve all permissionsfunction getAllPermissions() {}    return $stmt->execute(['forum_id' => $forum_id, 'role_id' => $role_id, 'permissions' => $permissions]);    $stmt = $pdo->prepare("REPLACE INTO forum_permissions (forum_id, role_id, permissions) VALUES (:forum_id, :role_id, :permissions)");    global $pdo;    // Function to set permissions for a role on a forumfunction setForumPermissions($forum_id, $role_id, $permissions) {}    return $stmt->fetch();    $stmt->execute(['forum_id' => $forum_id, 'user_id' => $user_id]);    ");        WHERE permissions.forum_id = :forum_id AND users.id = :user_id        JOIN users ON permissions.role_id = users.role        FROM forum_permissions as permissions        SELECT permissions.*    $stmt = $pdo->prepare("    global $pdo;    // Function to get a user's permissions for a forumfunction getForumPermissions($forum_id, $user_id) {}    return $stmt->fetchAll();    $stmt->execute(['user_id' => $user_id]);    $stmt = $pdo->prepare("SELECT * FROM activity_log WHERE user_id = :user_id ORDER BY timestamp DESC");    global $pdo;    // Function to retrieve a user's activity logfunction getUserActivityLog($user_id) {}    return $stmt->fetchAll();    $stmt->execute(['role' => $role]);    $stmt = $pdo->prepare("SELECT * FROM users WHERE role = :role");    global $pdo;    // Function to retrieve users by their rolefunction getUsersByRole($role) {}    return $stmt->fetchAll(PDO::FETCH_COLUMN);    $stmt = $pdo->query("SELECT DISTINCT role FROM users");    global $pdo;    // Function to retrieve all user rolesfunction getAllRoles() {}    return false;    }        return $stmt->execute(['user_id' => $user_id, 'password' => $new_password_hash]);        $stmt = $pdo->prepare("UPDATE users SET password = :password WHERE id = :user_id");        $new_password_hash = password_hash($new_password, PASSWORD_BCRYPT);    if ($user && password_verify($current_password, $user['password'])) {        $user = $stmt->fetch();    $stmt->execute(['user_id' => $user_id]);    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = :user_id");    global $pdo;    // Function to change a user's passwordfunction changeUserPassword($user_id, $current_password, $new_password) {}    return $stmt->execute(['user_id' => $user_id, 'username' => $username, 'email' => $email, 'bio' => $bio]);    $stmt = $pdo->prepare("UPDATE users SET username = :username, email = :email, bio = :bio WHERE id = :user_id");    global $pdo;    // Function to update a user's profile informationfunction updateUserProfile($user_id, $username, $email, $bio) {}    return $stmt->fetch();    $stmt->execute(['user_id' => $user_id]);    ");        GROUP BY users.id        WHERE users.id = :user_id        LEFT JOIN comments ON users.id = comments.user_id        LEFT JOIN posts ON users.id = posts.user_id        FROM users        SELECT users.*, COUNT(posts.id) as post_count, COUNT(comments.id) as comment_count    $stmt = $pdo->prepare("    global $pdo;    // Function to get a user's profile informationfunction getUserProfile($user_id) {}    return $stmt->fetch();    $stmt->execute(['email' => $email]);    $stmt = $pdo->prepare("SELECT * FROM users WHERE email = :email");    global $pdo;    // Function to retrieve a user by their email addressfunction getUserByEmail($email) {}    return $stmt->fetchAll();    $stmt->execute(['keyword' => '%' . $keyword . '%']);    $stmt = $pdo->prepare("SELECT * FROM comments WHERE content LIKE :keyword");    global $pdo;    // Function to search comments by keywordfunction searchComments($keyword) {}    return $stmt->execute(['id' => $id, 'content' => $content]);    $stmt = $pdo->prepare("UPDATE comments SET content = :content WHERE id = :id");    global $pdo;    // Function to update a commentfunction updateComment($id, $content) {}    return $stmt->fetch();    $stmt->execute(['id' => $id]);    $stmt = $pdo->prepare("SELECT * FROM comments WHERE id = :id");    global $pdo;    // Function to retrieve a comment by its IDfunction getCommentById($id) {}    return $stmt->execute(['id' => $id]);    $stmt = $pdo->prepare("DELETE FROM comments WHERE id = :id");    global $pdo;    // Function to delete a commentfunction deleteComment($id) {}    return $stmt->execute(['post_id' => $post_id, 'user_id' => $user_id, 'content' => $content]);    $stmt = $pdo->prepare("INSERT INTO comments (post_id, user_id, content) VALUES (:post_id, :user_id, :content)");    global $pdo;    // Function to create a new commentfunction createComment($post_id, $user_id, $content) {}    return $stmt->fetchAll();    $stmt->execute(['post_id' => $post_id]);    $stmt = $pdo->prepare("SELECT * FROM comments WHERE post_id = :post_id");    global $pdo;    // Function to get all comments for a postfunction getPostComments($post_id) {}    return $stmt->fetchAll();    $stmt->execute(['user_id' => $user_id]);    $stmt = $pdo->prepare("SELECT * FROM comments WHERE user_id = :user_id");    global $pdo;    // Function to get all comments by a userfunction getUserComments($user_id) {}    return $stmt->fetchAll();    $stmt->execute(['user_id' => $user_id]);    $stmt = $pdo->prepare("SELECT * FROM posts WHERE user_id = :user_id");    global $pdo;    // Function to get all posts by a userfunction getUserPosts($user_id) {}    return $stmt->fetch();    $stmt->execute(['forum_id' => $forum_id]);    ");        WHERE posts.forum_id = :forum_id        JOIN users ON posts.user_id = users.id        FROM posts        SELECT COUNT(posts.id) as post_count, MAX(posts.created_at) as last_post_time, users.username as last_user    $stmt = $pdo->prepare("    global $pdo;    // Function to get activity for a forum (post count, last active user, etc.)function getForumActivity($forum_id) {}    file_put_contents($logFile, implode(PHP_EOL, $newLogs));    $newLogs = preg_grep('/User ' . preg_quote($user_id, '/') . ':/', $logs, PREG_GREP_INVERT);    $logs = file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);    $logFile = __DIR__ . '/../logs/system.log';    // Function to clear logs for a specific userfunction clearUserLogs($user_id) {}    return array_slice($userLogs, 0, $limit);    $userLogs = preg_grep('/User ' . preg_quote($user_id, '/') . ':/', $logs);    $logs = array_reverse(file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES));    $logFile = __DIR__ . '/../logs/system.log';    // Function to retrieve logs for a specific userfunction getUserLogs($user_id, $limit = 100) {}    file_put_contents($logFile, "");    $logFile = __DIR__ . '/../logs/system.log';    // Function to clear the system logsfunction clearSystemLogs() {}    return array_slice($logs, 0, $limit);    $logs = array_reverse(file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES));    $logFile = __DIR__ . '/../logs/system.log';    // Function to retrieve system logsfunction getSystemLogs($limit = 100) {}    $pdo->exec("SET FOREIGN_KEY_CHECKS=1"); // Enable foreign key checks    $pdo->exec($sql);    $sql = file_get_contents($backupFile);    }        $pdo->exec("TRUNCATE TABLE $table"); // Truncate table    foreach ($tables as $table) {    $tables = $pdo->query("SHOW TABLES")->fetchAll(PDO::FETCH_COLUMN);    $pdo->exec("SET FOREIGN_KEY_CHECKS=0"); // Disable foreign key checks    global $pdo;    // Function to restore the database from a backupfunction restoreDatabase($backupFile) {}    $pdo->exec("SET FOREIGN_KEY_CHECKS=1"); // Enable foreign key checks    }        $pdo->exec("DELETE FROM $table"); // Truncate table    foreach ($tables as $table) {    $tables = $pdo->query("SHOW TABLES")->fetchAll(PDO::FETCH_COLUMN);    $pdo->exec("SET FOREIGN_KEY_CHECKS=0"); // Disable foreign key checks    global $pdo;    // Function to back up the databasefunction backupDatabase($backupFile) {}    return $stmt->execute(['key' => $key]);    $stmt = $pdo->prepare("DELETE FROM settings WHERE `key` = :key");    global $pdo;    // Function to delete a settingfunction deleteSetting($key) {}    return $stmt->execute(['key' => $key, 'value' => $value]);    $stmt = $pdo->prepare("REPLACE INTO settings (`key`, value) VALUES (:key, :value)");    global $pdo;    // Function to update or insert a settingfunction setSetting($key, $value) {}    return $setting ? $setting['value'] : null;    $setting = $stmt->fetch();    $stmt->execute(['key' => $key]);    $stmt = $pdo->prepare("SELECT value FROM settings WHERE `key` = :key");    global $pdo;    // Function to retrieve a specific setting by keyfunction getSetting($key) {}    return $stmt->fetchAll();    $stmt = $pdo->query("SELECT * FROM settings");    global $pdo;    // Function to retrieve all settingsfunction getAllSettings() {}    return $stmt->execute(['id' => $user_id]);    $stmt = $pdo->prepare("UPDATE users SET reset_token = NULL WHERE id = :id");    global $pdo;    // Function to clear the password reset token for a userfunction clearPasswordResetToken($user_id) {}    return $stmt->execute(['id' => $user_id, 'token' => $token]);    $stmt = $pdo->prepare("UPDATE users SET reset_token = :token WHERE id = :id");    global $pdo;    // Function to set a password reset token for a userfunction setPasswordResetToken($user_id, $token) {}    return $stmt->fetch();    $stmt->execute(['token' => $token]);    $stmt = $pdo->prepare("SELECT * FROM users WHERE reset_token = :token");    global $pdo;    // Function to retrieve a user by their password reset tokenfunction getUserByResetToken($token) {}    mail($email, $subject, $message);    $message .= "https://yourdomain.com/verify_email.php?token=" . $token;    $message = "Please click the following link to verify your email address: ";    $subject = "Email Verification";    // Function to send a verification emailfunction sendVerificationEmail($email, $token) {}    }        sendVerificationEmail($user['email'], $token);        $token = $user['verification_code'];    if ($user) {        $user = $stmt->fetch();    $stmt->execute(['id' => $user_id]);    $stmt = $pdo->prepare("SELECT email, verification_code FROM users WHERE id = :id");    global $pdo;    // Function to resend the verification emailfunction resendVerificationEmail($user_id) {}    return $stmt->execute(['id' => $id, 'verification_code' => $verification_code]);    $stmt = $pdo->prepare("UPDATE users SET verified = 1 WHERE id = :id AND verification_code = :verification_code");    global $pdo;    // Function to verify a user's email addressfunction verifyUser($id, $verification_code) {}    return $stmt->execute(['token' => $token, 'password' => $passwordHash]);    $stmt = $pdo->prepare("UPDATE users SET password = :password WHERE reset_token = :token");    $passwordHash = password_hash($new_password, PASSWORD_BCRYPT);    global $pdo;    // Function to reset a user's passwordfunction resetPassword($token, $new_password) {}    mail($email, $subject, $message);    $message .= "https://yourdomain.com/reset_password.php?token=" . $token;    $message = "To reset your password, please click the following link: ";    $subject = "Password Reset Request";    // Function to send a password reset emailfunction sendPasswordResetEmail($email, $token) {}    return $stmt->fetch();    $stmt->execute(['username' => $username]);    $stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username");    global $pdo;    // Function to retrieve a user by their usernamefunction getUserByUsername($username) {}    return $stmt->fetchAll();    $stmt->execute();    $stmt->bindValue('limit', (int)$limit, PDO::PARAM_INT);    ");        LIMIT :limit        ORDER BY posts.views DESC        JOIN users ON posts.user_id = users.id        JOIN forums ON posts.forum_id = forums.id        FROM posts        SELECT posts.*, forums.name as forum_name, users.username as author    $stmt = $pdo->prepare("    global $pdo;    // Function to get popular posts based on views or likesfunction getPopularPosts($limit = 5) {}    return $stmt->fetchAll();    $stmt->execute();    $stmt->bindValue('limit', (int)$limit, PDO::PARAM_INT);    ");        LIMIT :limit        ORDER BY posts.created_at DESC        JOIN users ON posts.user_id = users.id        JOIN forums ON posts.forum_id = forums.id        FROM posts        SELECT posts.*, forums.name as forum_name, users.username as author    $stmt = $pdo->prepare("    global $pdo;    // Function to get recent posts across all forumsfunction getRecentPosts($limit = 5) {}    return $stmt->fetch();    $stmt->execute(['user_id' => $user_id]);    ");        WHERE users.id = :user_id        JOIN users ON posts.user_id = users.id        FROM posts        SELECT COUNT(posts.id) as post_count, users.registered_at    $stmt = $pdo->prepare("    global $pdo;    // Function to get statistics for a user (post count, registration date, etc.)function getUserStatistics($user_id) {}    return $stmt->fetch();    $stmt->execute(['forum_id' => $forum_id]);    ");        WHERE posts.forum_id = :forum_id        JOIN users ON posts.user_id = users.id        FROM posts        SELECT COUNT(posts.id) as post_count, MAX(posts.created_at) as last_post_time, users.username as last_user    $stmt = $pdo->prepare("    global $pdo;    // Function to get statistics for a forum (post count, last active user, etc.)function getForumStatistics($forum_id) {}    return $stmt->execute(['user_id' => $user_id, 'action' => $action]);    $stmt = $pdo->prepare("INSERT INTO activity_log (user_id, action, timestamp) VALUES (:user_id, :action, NOW())");    global $pdo;    // Function to log a user's activityfunction logUserActivity($user_id, $action) {}    return $stmt->fetchAll();    $stmt->execute(['user_id' => $user_id]);    $stmt = $pdo->prepare("SELECT * FROM activity_log WHERE user_id = :user_id ORDER BY timestamp DESC");    global $pdo;    // Function to get a user's activity (posts, comments, etc.)function getUserActivity($user_id) {}    return $stmt->execute(['id' => $id, 'username' => $username, 'email' => $email, 'role' => $role]);    $stmt = $pdo->prepare("UPDATE users SET username = :username, email = :email, role = :role WHERE id = :id");    global $pdo;    // Function to update a user's informationfunction updateUser($id, $username, $email, $role) {}    return $stmt->execute(['id' => $id]);    $stmt = $pdo->prepare("DELETE FROM users WHERE id = :id");    global $pdo;    // Function to delete a userfunction deleteUser($id) {}    return $stmt->fetchAll();    $stmt = $pdo->query("SELECT * FROM users");    global $pdo;    // Function to retrieve all usersfunction getAllUsers() {}    return $stmt->execute(['id' => $user_id, 'role' => $role]);    $stmt = $pdo->prepare("UPDATE users SET role = :role WHERE id = :id");    global $pdo;    // Function to set a user's rolefunction setUserRole($user_id, $role) {}    return $user ? $user['role'] : null;    $user = $stmt->fetch();    $stmt->execute(['id' => $user_id]);    $stmt = $pdo->prepare("SELECT role FROM users WHERE id = :id");    global $pdo;    // Function to get a user's role by their IDfunction getUserRole($user_id) {}    session_destroy();    session_unset();    // Function to log out a userfunction logoutUser() {}    return false;    }        return true;        $_SESSION['role'] = $user['role'];        $_SESSION['last_activity'] = time();        $_SESSION['user_id'] = $user['id'];    if ($user && password_verify($password, $user['password'])) {        $user = $stmt->fetch();    $stmt->execute(['email' => $email]);    $stmt = $pdo->prepare("SELECT * FROM users WHERE email = :email");    global $pdo;    // Function to log in a userfunction loginUser($email, $password) {}    return $stmt->execute(['username' => $username, 'email' => $email, 'password' => $passwordHash]);    $stmt = $pdo->prepare("INSERT INTO users (username, email, password) VALUES (:username, :email, :password)");    $passwordHash = password_hash($password, PASSWORD_BCRYPT);    global $pdo;    // Function to register a new userfunction registerUser($username, $email, $password) {}    return $stmt->fetchAll();    $stmt->execute(['keyword' => '%' . $keyword . '%']);    $stmt = $pdo->prepare("SELECT * FROM posts WHERE content LIKE :keyword");    global $pdo;    // Function to search posts by keywordfunction searchPosts($keyword) {}    return $stmt->execute(['id' => $id, 'content' => $content]);    $stmt = $pdo->prepare("UPDATE posts SET content = :content WHERE id = :id");    global $pdo;    // Function to update a postfunction updatePost($id, $content) {}    return $stmt->fetch();    $stmt->execute(['id' => $id]);    $stmt = $pdo->prepare("SELECT * FROM posts WHERE id = :id");    global $pdo;    // Function to retrieve a post by its IDfunction getPostById($id) {}    return $stmt->execute(['id' => $id]);    $stmt = $pdo->prepare("DELETE FROM posts WHERE id = :id");    global $pdo;    // Function to delete a postfunction deletePost($id) {}    return $stmt->execute(['forum_id' => $forum_id, 'user_id' => $user_id, 'content' => $content]);    $stmt = $pdo->prepare("INSERT INTO posts (forum_id, user_id, content) VALUES (:forum_id, :user_id, :content)");    global $pdo;    // Function to create a new postfunction createPost($forum_id, $user_id, $content) {}    return $stmt->fetchAll();    $stmt->execute(['forum_id' => $forum_id]);    $stmt = $pdo->prepare("SELECT * FROM posts WHERE forum_id = :forum_id");    global $pdo;    // Function to retrieve posts by forum IDfunction getPostsByForumId($forum_id) {}    return $stmt->execute(['id' => $id, 'name' => $name, 'description' => $description]);    $stmt = $pdo->prepare("UPDATE forums SET name = :name, description = :description WHERE id = :id");    global $pdo;    // Function to update a forumfunction updateForum($id, $name, $description) {}    return $stmt->fetch();    $stmt->execute(['id' => $id]);    $stmt = $pdo->prepare("SELECT * FROM forums WHERE id = :id");    global $pdo;    // Function to retrieve a forum by its IDfunction getForumById($id) {}    return $stmt->execute(['id' => $id]);    $stmt = $pdo->prepare("DELETE FROM forums WHERE id = :id");    global $pdo;    // Function to delete a forumfunction deleteForum($id) {}    return $stmt->execute(['name' => $name, 'description' => $description]);    $stmt = $pdo->prepare("INSERT INTO forums (name, description) VALUES (:name, :description)");    global $pdo;    // Function to create a new forumfunction createForum($name, $description) {}    return $stmt->fetchAll();    $stmt = $pdo->query("SELECT * FROM forums");    global $pdo;    // Function to retrieve all forumsfunction getAllForums() {}    return $stmt->fetch();    $stmt->execute(['id' => $id]);    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");    global $pdo; // Assuming $pdo is your PDO connection    // Function to retrieve a user by their IDfunction getUserById($id) {}    }        $stmt->execute(['role_id' => $role_id, 'permission_id' => $permission_id]);        $stmt = $pdo->prepare("INSERT INTO role_permissions (role_id, permission_id) VALUES (:role_id, :permission_id)");    foreach ($permission_ids as $permission_id) {        $stmt->execute(['role_id' => $role_id]);    $stmt = $pdo->prepare("DELETE FROM role_permissions WHERE role_id = :role_id");    global $pdo;    // Function to set permissions for a rolefunction setRolePermissions($role_id, $permission_ids) {}    return $stmt->fetchAll();    $stmt->execute(['role_id' => $role_id]);    ");        WHERE permissions.role_id = :role_id        FROM role_permissions as permissions        SELECT permissions.*    $stmt = $pdo->prepare("    global $pdo;    // Function to get permissions for a specific rolefunction getRolePermissions($role_id) {}    return $stmt->fetchAll();    $stmt = $pdo->query("SELECT * FROM permissions");    global $pdo;    // Function to retrieve all permissionsfunction getAllPermissions() {}    return $stmt->execute(['forum_id' => $forum_id, 'role_id' => $role_id, 'permissions' => $permissions]);    $stmt = $pdo->prepare("REPLACE INTO forum_permissions (forum_id, role_id, permissions) VALUES (:forum_id, :role_id, :permissions)");    global $pdo;    // Function to set permissions for a role on a forumfunction setForumPermissions($forum_id, $role_id, $permissions) {}    return $stmt->fetch();    $stmt->execute(['forum_id' => $forum_id, 'user_id' => $user_id]);    ");        WHERE permissions.forum_id = :forum_id AND users.id = :user_id        JOIN users ON permissions.role_id = users.role        FROM forum_permissions as permissions        SELECT permissions.*    $stmt = $pdo->prepare("    global $pdo;    // Function to get a user's permissions for a forumfunction getForumPermissions($forum_id, $user_id) {}    return $stmt->fetchAll();    $stmt->execute(['user_id' => $user_id]);    $stmt = $pdo->prepare("SELECT * FROM activity_log WHERE user_id = :user_id ORDER BY timestamp DESC");    global $pdo;    // Function to retrieve a user's activity logfunction getUserActivityLog($user_id) {}    return $stmt->fetchAll();    $stmt->execute(['role' => $role]);    $stmt = $pdo->prepare("SELECT * FROM users WHERE role = :role");    global $pdo;    // Function to retrieve users by their rolefunction getUsersByRole($role) {}    return $stmt->fetchAll(PDO::FETCH_COLUMN);    $stmt = $pdo->query("SELECT DISTINCT role FROM users");    global $pdo;    // Function to retrieve all user rolesfunction getAllRoles() {}    return false;    }        return $stmt->execute(['user_id' => $user_id, 'password' => $new_password_hash]);        $stmt = $pdo->prepare("UPDATE users SET password = :password WHERE id = :user_id");        $new_password_hash = password_hash($new_password, PASSWORD_BCRYPT);    if ($user && password_verify($current_password, $user['password'])) {        $user = $stmt->fetch();    $stmt->execute(['user_id' => $user_id]);    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = :user_id");    global $pdo;    // Function to change a user's passwordfunction changeUserPassword($user_id, $current_password, $new_password) {}    return $stmt->execute(['user_id' => $user_id, 'username' => $username, 'email' => $email, 'bio' => $bio]);    $stmt = $pdo->prepare("UPDATE users SET username = :username, email = :email, bio = :bio WHERE id = :user_id");    global $pdo;    // Function to update a user's profile informationfunction updateUserProfile($user_id, $username, $email, $bio) {}    return $stmt->fetch();    $stmt->execute(['user_id' => $user_id]);    ");        GROUP BY users.id        WHERE users.id = :user_id        LEFT JOIN comments ON users.id = comments.user_id        LEFT JOIN posts ON users.id = posts.user_id        FROM users        SELECT users.*, COUNT(posts.id) as post_count, COUNT(comments.id) as comment_count    $stmt = $pdo->prepare("    global $pdo;    // Function to get a user's profile informationfunction getUserProfile($user_id) {}    return $stmt->fetch();    $stmt->execute(['email' => $email]);    $stmt = $pdo->prepare("SELECT * FROM users WHERE email = :email");    global $pdo;    // Function to retrieve a user by their email addressfunction getUserByEmail($email) {}    return $stmt->fetchAll();    $stmt->execute(['keyword' => '%' . $keyword . '%']);    $stmt = $pdo->prepare("SELECT * FROM comments WHERE content LIKE :keyword");    global $pdo;    // Function to search comments by keywordfunction searchComments($keyword) {}    return $stmt->execute(['id' => $id, 'content' => $content]);    $stmt = $pdo->prepare("UPDATE comments SET content = :content WHERE id = :id");    global $pdo;    // Function to update a commentfunction updateComment($id, $content) {}    return $stmt->fetch();    $stmt->execute(['id' => $id]);    $stmt = $pdo->prepare("SELECT * FROM comments WHERE id = :id");    global $pdo;    // Function to retrieve a comment by its IDfunction getCommentById($id) {}    return $stmt->execute(['id' => $id]);    $stmt = $pdo->prepare("DELETE FROM comments WHERE id = :id");    global $pdo;    // Function to delete a commentfunction deleteComment($id) {}    return $stmt->execute(['post_id' => $post_id, 'user_id' => $user_id, 'content' => $content]);    $stmt = $pdo->prepare("INSERT INTO comments (post_id, user_id, content) VALUES (:post_id, :user_id, :content)");    global $pdo;    // Function to create a new commentfunction createComment($post_id, $user_id, $content) {}    return $stmt->fetchAll();    $stmt->execute(['post_id' => $post_id]);    $stmt = $pdo->prepare("SELECT * FROM comments WHERE post_id = :post_id");    global $pdo;    // Function to get all comments for a postfunction getPostComments($post_id) {}    return $stmt->fetchAll();    $stmt->execute(['user_id' => $user_id]);    $stmt = $pdo->prepare("SELECT * FROM comments WHERE user_id = :user_id");    global $pdo;    // Function to get all comments by a userfunction getUserComments($user_id) {}    return $stmt->fetchAll();    $stmt->execute(['user_id' => $user_id]);    $stmt = $pdo->prepare("SELECT * FROM posts WHERE user_id = :user_id");    global $pdo;    // Function to get all posts by a userfunction getUserPosts($user_id) {}    return $stmt->fetch();    $stmt->execute(['forum_id' => $forum_id]);    ");        WHERE posts.forum_id = :forum_id        JOIN users ON posts.user_id = users.id        FROM posts        SELECT COUNT(posts.id) as post_count, MAX(posts.created_at) as last_post_time, users.username as last_user    $stmt = $pdo->prepare("    global $pdo;    // Function to get activity for a forum (post count, last active user, etc.)function getForumActivity($forum_id) {}    file_put_contents($logFile, implode(PHP_EOL, $newLogs));    $newLogs = preg_grep('/User ' . preg_quote($user_id, '/') . ':/', $logs, PREG_GREP_INVERT);    $logs = file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);    $logFile = __DIR__ . '/../logs/system.log';    // Function to clear logs for a specific userfunction clearUserLogs($user_id) {}    return array_slice($userLogs, 0, $limit);    $userLogs = preg_grep('/User ' . preg_quote($user_id, '/') . ':/', $logs);    $logs = array_reverse(file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES));    $logFile = __DIR__ . '/../logs/system.log';    // Function to retrieve logs for a specific userfunction getUserLogs($user_id, $limit = 100) {}    file_put_contents($logFile, "");    $logFile = __DIR__ . '/../logs/system.log';    // Function to clear the system logsfunction clearSystemLogs() {}    return array_slice($logs, 0, $limit);    $logs = array_reverse(file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES));    $logFile = __DIR__ . '/../logs/system.log';    // Function to retrieve system logsfunction getSystemLogs($limit = 100) {}    $pdo->exec("SET FOREIGN_KEY_CHECKS=1"); // Enable foreign key checks    $pdo->exec($sql);    $sql = file_get_contents($backupFile);    }        $pdo->exec("TRUNCATE TABLE $table"); // Truncate table    foreach ($tables as $table) {    $tables = $pdo->query("SHOW TABLES")->fetchAll(PDO::FETCH_COLUMN);    $pdo->exec("SET FOREIGN_KEY_CHECKS=0"); // Disable foreign key checks    global $pdo;    // Function to restore the database from a backupfunction restoreDatabase($backupFile) {}    $pdo->exec("SET FOREIGN_KEY_CHECKS=1"); // Enable foreign key checks    }        $pdo->exec("DELETE FROM $table"); // Truncate table    foreach ($tables as $table) {    $tables = $pdo->query("SHOW TABLES")->fetchAll(PDO::FETCH_COLUMN);    $pdo->exec("SET FOREIGN_KEY_CHECKS=0"); // Disable foreign key checks    global $pdo;    // Function to back up the databasefunction backupDatabase($backupFile) {}    return $stmt->execute(['key' => $key]);    $stmt = $pdo->prepare("DELETE FROM settings WHERE `key` = :key");    global $pdo;    // Function to delete a settingfunction deleteSetting($key) {}    return $stmt->execute(['key' => $key, 'value' => $value]);    $stmt = $pdo->prepare("REPLACE INTO settings (`key`, value) VALUES (:key, :value)");    global $pdo;    // Function to update or insert a settingfunction setSetting($key, $value) {}    return $setting ? $setting['value'] : null;    $setting = $stmt->fetch();    $stmt->execute(['key' => $key]);    $stmt = $pdo->prepare("SELECT value FROM settings WHERE `key` = :key");    global $pdo;    // Function to retrieve a specific setting by keyfunction getSetting($key) {}    return $stmt->fetchAll();    $stmt = $pdo->query("SELECT * FROM settings");    global $pdo;    // Function to retrieve all settingsfunction getAllSettings() {}    return $stmt->execute(['id' => $user_id]);    $stmt = $pdo->prepare("UPDATE users SET reset_token = NULL WHERE id = :id");    global $pdo;    // Function to clear the password reset token for a userfunction clearPasswordResetToken($user_id) {}    return $stmt->execute(['id' => $user_id, 'token' => $token]);    $stmt = $pdo->prepare("UPDATE users SET reset_token = :token WHERE id = :id");    global $pdo;    // Function to set a password reset token for a userfunction setPasswordResetToken($user_id, $token) {}    return $stmt->fetch();    $stmt->execute(['token' => $token]);    $stmt = $pdo->prepare("SELECT * FROM users WHERE reset_token = :token");    global $pdo;    // Function to retrieve a user by their password reset tokenfunction getUserByResetToken($token) {}    mail($email, $subject, $message);    $message .= "https://yourdomain.com/verify_email.php?token=" . $token;    $message = "Please click the following link to verify your email address: ";    $subject = "Email Verification";    // Function to send a verification emailfunction sendVerificationEmail($email, $token) {}    }        sendVerificationEmail($user['email'], $token);        $token = $user['verification_code'];    if ($user) {        $user = $stmt->fetch();    $stmt->execute(['id' => $user_id]);    $stmt = $pdo->prepare("SELECT email, verification_code FROM users WHERE id = :id");    global $pdo;    // Function to resend the verification emailfunction resendVerificationEmail($user_id) {}    return $stmt->execute(['id' => $id, 'verification_code' => $verification_code]);    $stmt = $pdo->prepare("UPDATE users SET verified = 1 WHERE id = :id AND verification_code = :verification_code");    global $pdo;    // Function to verify a user's email addressfunction verifyUser($id, $verification_code) {}    return $stmt->execute(['token' => $token, 'password' => $passwordHash]);    $stmt = $pdo->prepare("UPDATE users SET password = :password WHERE reset_token = :token");    $passwordHash = password_hash($new_password, PASSWORD_BCRYPT);    global $pdo;    // Function to reset a user's passwordfunction resetPassword($token, $new_password) {}    mail($email, $subject, $message);    $message .= "https://yourdomain.com/reset_password.php?token=" . $token;    $message = "To reset your password, please click the following link: ";    $subject = "Password Reset Request";    // Function to send a password reset emailfunction sendPasswordResetEmail($email, $token) {}    return $stmt->fetch();    $stmt->execute(['username' => $username]);    $stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username");    global $pdo;    // Function to retrieve a user by their usernamefunction getUserByUsername($username) {}    return $stmt->fetchAll();    $stmt->execute();    $stmt->bindValue('limit', (int)$limit, PDO::PARAM_INT);    ");        LIMIT :limit        ORDER BY posts.views DESC        JOIN users ON posts.user_id = users.id        JOIN forums ON posts.forum_id = forums.id        FROM posts        SELECT posts.*, forums.name as forum_name, users.username as author    $stmt = $pdo->prepare("    global $pdo;    // Function to get popular posts based on views or likesfunction getPopularPosts($limit = 5) {}    return $stmt->fetchAll();    $stmt->execute();    $stmt->bindValue('limit', (int)$limit, PDO::PARAM_INT);    ");        LIMIT :limit        ORDER BY posts.created_at DESC        JOIN users ON posts.user_id = users.id        JOIN forums ON posts.forum_id = forums.id        FROM posts        SELECT posts.*, forums.name as forum_name, users.username as author    $stmt = $pdo->prepare("    global $pdo;    // Function to get recent posts across all forumsfunction getRecentPosts($limit = 5) {}    return $stmt->fetch();    $stmt->execute(['user_id' => $user_id]);    ");        WHERE users.id = :user_id        JOIN users ON posts.user_id = users.id        FROM posts        SELECT COUNT(posts.id) as post_count, users.registered_at    $stmt = $pdo->prepare("    global $pdo;    // Function to get statistics for a user (post count, registration date, etc.)function getUserStatistics($user_id) {}    return $stmt->fetch();    $stmt->execute(['forum_id' => $forum_id]);    ");        WHERE posts.forum_id = :forum_id        JOIN users ON posts.user_id = users.id        FROM posts        SELECT COUNT(posts.id) as post_count, MAX(posts.created_at) as last_post_time, users.username as last_user    $stmt = $pdo->prepare("    global $pdo;    // Function to get statistics for a forum (post count, last active user, etc.)function getForumStatistics($forum_id) {}    return $stmt->execute(['user_id' => $user_id, 'action' => $action]);    $stmt = $pdo->prepare("INSERT INTO activity_log (user_id, action, timestamp) VALUES (:user_id, :action, NOW())");    global $pdo;    // Function to log a user's activityfunction logUserActivity($user_id, $action) {}    return $stmt->fetchAll();    $stmt->execute(['user_id' => $user_id]);    $stmt = $pdo->prepare("SELECT * FROM activity_log WHERE user_id = :user_id ORDER BY timestamp DESC");    global $pdo;    // Function to get a user's activity (posts, comments, etc.)function getUserActivity($user_id) {}    return $stmt->execute(['id' => $id, 'username' => $username, 'email' => $email, 'role' => $role]);    $stmt = $pdo->prepare("UPDATE users SET username = :username, email = :email, role = :role WHERE id = :id");    global $pdo;    // Function to update a user's informationfunction updateUser($id, $username, $email, $role) {}    return $stmt->execute(['id' => $id]);    $stmt = $pdo->prepare("DELETE FROM users WHERE id = :id");    global $pdo;    // Function to delete a userfunction deleteUser($id) {}    return $stmt->fetchAll();    $stmt = $pdo->query("SELECT * FROM users");    global $pdo;    // Function to retrieve all usersfunction getAllUsers() {}    return $stmt->execute(['id' => $user_id, 'role' => $role]);    $stmt = $pdo->prepare("UPDATE users SET role = :role WHERE id = :id");    global $pdo;    // Function to set a user's rolefunction setUserRole($user_id, $role) {}    return $user ? $user['role'] : null;    $user = $stmt->fetch();    $stmt->execute(['id' => $user_id]);    $stmt = $pdo->prepare("SELECT role FROM users WHERE id = :id");    global $pdo;    // Function to get a user's role by their IDfunction getUserRole($user_id) {}    session_destroy();    session_unset();    // Function to log out a userfunction logoutUser() {}    return false;    }        return true;        $_SESSION['role'] = $user['role'];        $_SESSION['last_activity'] = time();        $_SESSION['user_id'] = $user['id'];    if ($user && password_verify($password, $user['password'])) {        $user = $stmt->fetch();    $stmt->execute(['email' => $email]);    $stmt = $pdo->prepare("SELECT * FROM users WHERE email = :email");    global $pdo;    // Function to log in a userfunction loginUser($email, $password) {}    return $stmt->execute(['username' => $username, 'email' => $email, 'password' => $passwordHash]);    $stmt = $pdo->prepare("INSERT INTO users (username, email, password) VALUES (:username, :email, :password)");    $passwordHash = password_hash($password, PASSWORD_BCRYPT);    global $pdo;    // Function to register a new userfunction registerUser($username, $email, $password) {}    return $stmt->fetchAll();    $stmt->execute(['keyword' => '%' . $keyword . '%']);    $stmt = $pdo->prepare("SELECT * FROM posts WHERE content LIKE :keyword");    global $pdo;    // Function to search posts by keywordfunction searchPosts($keyword) {}    return $stmt->execute(['id' => $id, 'content' => $content]);    $stmt = $pdo->prepare("UPDATE posts SET content = :content WHERE id = :id");    global $pdo;    // Function to update a postfunction updatePost($id, $content) {}    return $stmt->fetch();    $stmt->execute(['id' => $id]);    $stmt = $pdo->prepare("SELECT * FROM posts WHERE id = :id");    global $pdo;    // Function to retrieve a post by its IDfunction getPostById($id) {}    return $stmt->execute(['id' => $id]);    $stmt = $pdo->prepare("DELETE FROM posts WHERE id = :id");    global $pdo;    // Function to delete a postfunction deletePost($id) {}    return $stmt->execute(['forum_id' => $forum_id, 'user_id' => $user_id, 'content' => $content]);    $stmt = $pdo->prepare("INSERT INTO posts (forum_id, user_id, content) VALUES (:forum_id, :user_id, :content)");    global $pdo;    // Function to create a new postfunction createPost($forum_id, $user_id, $content) {}    return $stmt->fetchAll();    $stmt->execute(['forum_id' => $forum_id]);    $stmt = $pdo->prepare("SELECT * FROM posts WHERE forum_id = :forum_id");    global $pdo;    // Function to retrieve posts by forum IDfunction getPostsByForumId($forum_id) {}    return $stmt->execute(['id' => $id, 'name' => $name, 'description' => $description]);    $stmt = $pdo->prepare("UPDATE forums SET name = :name, description = :description WHERE id = :id");    global $pdo;    // Function to update a forumfunction updateForum($id, $name, $description) {}    return $stmt->fetch();    $stmt->execute(['id' => $id]);    $stmt = $pdo->prepare("SELECT * FROM forums WHERE id = :id");    global $pdo;    // Function to retrieve a forum by its IDfunction getForumById($id) {}    return $stmt->execute(['id' => $id]);    $stmt = $pdo->prepare("DELETE FROM forums WHERE id = :id");    global $pdo;    // Function to delete a forum    // Function to delete a forum
    global $pdo;
    $stmt = $pdo->prepare("DELETE FROM forums WHERE id = :id");
    return $stmt->execute(['id' => $id]);
}

function sanitizeInput($data) {
    // Function to sanitize user input
    return htmlspecialchars(strip_tags(trim($data)));
}