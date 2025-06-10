<?php
session_start();
require_once '../config/database.php';
require_once '../includes/auth.php';
require_once '../includes/functions.php';

// Check if the user is logged in and has admin privileges
if (!isLoggedIn() || !isAdmin()) {
    header('Location: ../pages/login.php');
    exit();
}

// Fetch users from the database
$users = getAllUsers();

if (isset($_POST['delete_user'])) {
    $userId = $_POST['user_id'];
    deleteUser($userId);
    header('Location: manage-users.php');
    exit();
}

if (isset($_POST['edit_user'])) {
    $userId = $_POST['user_id'];
    $user = getUserById($userId);
}

if (isset($_POST['update_user'])) {
    $userId = $_POST['user_id'];
    $username = $_POST['username'];
    $role = $_POST['role'];
    updateUser($userId, $username, $role);
    header('Location: manage-users.php');
    exit();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Manage Users</title>
    <link rel="stylesheet" href="../assets/css/style.css">
</head>
<body>
    <?php include '../includes/header.php'; ?>
    <div class="container">
        <h1>Manage Users</h1>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Username</th>
                    <th>Role</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($users as $user): ?>
                    <tr>
                        <td><?php echo htmlspecialchars($user['id']); ?></td>
                        <td><?php echo htmlspecialchars($user['username']); ?></td>
                        <td><?php echo htmlspecialchars($user['role']); ?></td>
                        <td>
                            <form method="post" action="">
                                <input type="hidden" name="user_id" value="<?php echo $user['id']; ?>">
                                <button type="submit" name="edit_user">Edit</button>
                                <button type="submit" name="delete_user">Delete</button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>

        <?php if (isset($user)): ?>
            <h2>Edit User</h2>
            <form method="post" action="">
                <input type="hidden" name="user_id" value="<?php echo $user['id']; ?>">
                <label for="username">Username:</label>
                <input type="text" name="username" value="<?php echo htmlspecialchars($user['username']); ?>" required>
                <label for="role">Role:</label>
                <select name="role">
                    <option value="user" <?php echo $user['role'] == 'user' ? 'selected' : ''; ?>>User</option>
                    <option value="admin" <?php echo $user['role'] == 'admin' ? 'selected' : ''; ?>>Admin</option>
                </select>
                <button type="submit" name="update_user">Update User</button>
            </form>
        <?php endif; ?>
    </div>
    <?php include '../includes/footer.php'; ?>
</body>
</html>