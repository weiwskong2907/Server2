<?php
session_start();
require_once '../config/database.php';
require_once '../classes/Forum.php';

$forum = new Forum($pdo);

// Handle form submissions for creating, editing, and deleting forums
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (isset($_POST['create_forum'])) {
        $forum_name = $_POST['forum_name'];
        $forum->createForum($forum_name);
    } elseif (isset($_POST['edit_forum'])) {
        $forum_id = $_POST['forum_id'];
        $forum_name = $_POST['forum_name'];
        $forum->editForum($forum_id, $forum_name);
    } elseif (isset($_POST['delete_forum'])) {
        $forum_id = $_POST['forum_id'];
        $forum->deleteForum($forum_id);
    }
}

// Fetch all forums for display
$forums = $forum->getAllForums();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Manage Forums</title>
    <link rel="stylesheet" href="../assets/css/style.css">
</head>
<body>
    <?php include '../includes/header.php'; ?>

    <h1>Manage Forums</h1>

    <form action="" method="POST">
        <input type="text" name="forum_name" placeholder="Forum Name" required>
        <button type="submit" name="create_forum">Create Forum</button>
    </form>

    <h2>Existing Forums</h2>
    <ul>
        <?php foreach ($forums as $forum): ?>
            <li>
                <?php echo htmlspecialchars($forum['name']); ?>
                <form action="" method="POST" style="display:inline;">
                    <input type="hidden" name="forum_id" value="<?php echo $forum['id']; ?>">
                    <input type="text" name="forum_name" value="<?php echo htmlspecialchars($forum['name']); ?>" required>
                    <button type="submit" name="edit_forum">Edit</button>
                    <button type="submit" name="delete_forum">Delete</button>
                </form>
            </li>
        <?php endforeach; ?>
    </ul>

    <?php include '../includes/footer.php'; ?>
</body>
</html>