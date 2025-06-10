<?php
session_start();
require_once '../config/database.php';
require_once '../includes/functions.php';

// Fetch forum categories
$forumCategories = getForumCategories($pdo);

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forum</title>
    <link rel="stylesheet" href="../assets/css/style.css">
</head>
<body>
    <?php include '../includes/header.php'; ?>

    <main>
        <h1>Forum Categories</h1>
        <div class="forum-categories">
            <?php if ($forumCategories): ?>
                <ul>
                    <?php foreach ($forumCategories as $category): ?>
                        <li>
                            <a href="thread.php?category_id=<?php echo $category['id']; ?>">
                                <?php echo htmlspecialchars($category['name']); ?>
                            </a>
                        </li>
                    <?php endforeach; ?>
                </ul>
            <?php else: ?>
                <p>No forum categories available.</p>
            <?php endif; ?>
        </div>
    </main>

    <?php include '../includes/footer.php'; ?>
</body>
</html>