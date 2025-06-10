<?php
session_start();
require_once '../config/database.php';
require_once '../includes/functions.php';
require_once '../includes/auth.php';

// Check if the user is logged in
if (!isLoggedIn()) {
    header('Location: login.php');
    exit();
}

// Get the thread ID from the URL
$thread_id = isset($_GET['id']) ? intval($_GET['id']) : 0;

// Fetch the thread details from the database
$forum = new Forum();
$thread = $forum->getThread($thread_id);

// Fetch posts associated with the thread
$posts = $forum->getPostsByThread($thread_id);

include '../includes/header.php';
?>

<div class="container">
    <h1><?php echo htmlspecialchars($thread['title']); ?></h1>
    <p><?php echo htmlspecialchars($thread['content']); ?></p>
    
    <h2>Posts</h2>
    <?php if ($posts): ?>
        <ul>
            <?php foreach ($posts as $post): ?>
                <li>
                    <strong><?php echo htmlspecialchars($post['author']); ?>:</strong>
                    <p><?php echo htmlspecialchars($post['content']); ?></p>
                </li>
            <?php endforeach; ?>
        </ul>
    <?php else: ?>
        <p>No posts yet. Be the first to reply!</p>
    <?php endif; ?>

    <h3>Add a Post</h3>
    <form action="add_post.php" method="POST">
        <input type="hidden" name="thread_id" value="<?php echo $thread_id; ?>">
        <textarea name="content" required></textarea>
        <button type="submit">Submit</button>
    </form>
</div>

<?php include '../includes/footer.php'; ?>