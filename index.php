<?php
session_start();
require_once 'config/config.php';
require_once 'config/database.php';
require_once 'includes/auth.php';
require_once 'includes/functions.php';

// Check if the user is logged in
if (isLoggedIn()) {
    header('Location: pages/forum.php'); // Redirect to the forum page if logged in
    exit();
}

// Include header
include 'includes/header.php';
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo SITE_NAME; ?> - Home</title>
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
    <div class="container">
        <h1>Welcome to <?php echo SITE_NAME; ?></h1>
        <p>Please <a href="pages/login.php">login</a> or <a href="pages/register.php">register</a> to continue.</p>
    </div>

    <?php include 'includes/footer.php'; ?>
</body>
</html>