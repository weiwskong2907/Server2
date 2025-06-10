<?php
session_start();

// Function to check if the user is logged in
function isLoggedIn() {
    return isset($_SESSION['user_id']);
}

// Function to log the user out
function logout() {
    session_unset();
    session_destroy();
    header("Location: index.php");
    exit();
}

// Function to validate session
function validateSession() {
    if (!isLoggedIn()) {
        header("Location: pages/login.php");
        exit();
    }
}
?>