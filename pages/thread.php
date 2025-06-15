<?php
define('BASE_PATH', dirname(__DIR__));
require_once BASE_PATH . '/config/bootstrap.php';

// Check if the user is logged in
if (!isLoggedIn()) {
    redirectWithMessage('login.php', 'Please login to view threads', 'error');
}

try {
    // Get the thread ID from the URL
    $thread_id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
    if (!$thread_id) {
        throw new Exception('Invalid thread ID');
    }

    // Fetch the thread details from the database
    $forum = new Forum();
    $thread = $forum->getThread($thread_id);
    
    if (!$thread) {
        throw new Exception('Thread not found');
    }

    // Fetch posts associated with the thread
    $posts = $forum->getPostsByThread($thread_id);

} catch (Exception $e) {
    redirectWithMessage('index.php', $e->getMessage(), 'error');
}

include BASE_PATH . '/includes/header.php';
?>

<div class="container">
    <h1><?= htmlspecialchars($thread['title']) ?></h1>
    <p><?= htmlspecialchars($thread['content']) ?></p>
    
    <h2>Posts</h2>
    <?php if ($posts): ?>
        <ul class="post-list">
            <?php foreach ($posts as $post): ?>
                <li class="post-item">
                    <div class="post-header">
                        <strong><?= htmlspecialchars($post['author']) ?></strong>
                        <span class="post-date"><?= date('M j, Y g:i A', strtotime($post['created_at'])) ?></span>
                    </div>
                    <div class="post-content">
                        <?= nl2br(htmlspecialchars($post['content'])) ?>
                    </div>
                </li>
            <?php endforeach; ?>
        </ul>
    <?php else: ?>
        <p class="no-posts">No posts yet. Be the first to reply!</p>
    <?php endif; ?>

    <div class="post-form">
        <h3>Add a Post</h3>
        <form action="add_post.php" method="POST" class="reply-form">
            <?= getCsrfToken() ?>
            <input type="hidden" name="thread_id" value="<?= $thread_id ?>">
            <div class="form-group">
                <textarea name="content" required class="form-control" 
                          placeholder="Write your reply here..."
                          minlength="<?= MIN_POST_LENGTH ?>" 
                          maxlength="<?= MAX_POST_LENGTH ?>"></textarea>
            </div>
            <button type="submit" class="btn btn-primary">Submit Reply</button>
        </form>
    </div>
</div>

<?php include BASE_PATH . '/includes/footer.php'; ?>