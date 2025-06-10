<?php
// register.php

require_once '../config/config.php';
require_once '../config/database.php';
require_once '../includes/auth.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = trim($_POST['username']);
    $email = trim($_POST['email']);
    $password = trim($_POST['password']);
    $invite_code = trim($_POST['invite_code']);

    // Validate invite code
    if (!isValidInviteCode($invite_code)) {
        $error = "Invalid invite code.";
    } else {
        // Register user
        $user = new User();
        $result = $user->register($username, $email, $password);

        if ($result) {
            header("Location: login.php?success=Registration successful. Please log in.");
            exit;
        } else {
            $error = "Registration failed. Please try again.";
        }
    }
}

function isValidInviteCode($code) {
    // Logic to validate invite code
    return true; // Placeholder for actual validation logic
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register</title>
    <link rel="stylesheet" href="../assets/css/style.css">
</head>
<body>
    <div class="container">
        <h2>Register</h2>
        <?php if (isset($error)): ?>
            <div class="error"><?php echo $error; ?></div>
        <?php endif; ?>
        <form action="register.php" method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="email" name="email" placeholder="Email" required>
            <input type="password" name="password" placeholder="Password" required>
            <input type="text" name="invite_code" placeholder="Invite Code" required>
            <button type="submit">Register</button>
        </form>
        <p>Already have an account? <a href="login.php">Login here</a>.</p>
    </div>
</body>
</html>