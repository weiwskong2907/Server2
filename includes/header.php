<?php
// header.php
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo isset($pageTitle) ? $pageTitle : 'Family and Friends Forum'; ?></title>
    <link rel="stylesheet" href="assets/css/style.css">
    <script src="assets/js/main.js" defer></script>
</head>
<body>
    <header>
        <h1>Welcome to the Family and Friends Forum</h1>
        <nav>
            <ul>
                <li><a href="index.php">Home</a></li>
                <li><a href="pages/forum.php">Forums</a></li>
                <li><a href="pages/login.php">Login</a></li>
                <li><a href="pages/register.php">Register</a></li>
            </ul>
        </nav>
    </header>
    <main>