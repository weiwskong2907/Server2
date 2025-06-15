<?php
if (!defined('BASE_PATH')) {
    exit('No direct script access allowed');
}

try {
    $forums = getAllForums();
    $recent_threads = getRecentThreads(5);
    $active_users = getActiveUsers(10);
} catch (Exception $e) {
    logError($e->getMessage());
    $error_message = DEBUG_MODE ? $e->getMessage() : 'An error occurred loading the page';
}
?>

<div class="container">
    <div class="welcome-section">
        <h1>Welcome to <?= SITE_NAME ?></h1>
        <?php if (isLoggedIn()): ?>
            <p>Welcome back, <?= htmlspecialchars($_SESSION['username']) ?>!</p>
        <?php else: ?>
            <p>Please <a href="login.php">login</a> or <a href="register.php">register</a> to participate.</p>
        <?php endif; ?>
    </div>

    <?php if (isset($error_message)): ?>
        <div class="alert alert-error">
            <?= htmlspecialchars($error_message) ?>
        </div>
    <?php endif; ?>

    <div class="forums-section">
        <h2>Forums</h2>
        <?php if (!empty($forums)): ?>
            <div class="forum-list">
                <?php foreach ($forums as $forum): ?>
                    <div class="forum-item">
                        <h3><a href="forum.php?id=<?= $forum['id'] ?>"><?= htmlspecialchars($forum['name']) ?></a></h3>
                        <p><?= htmlspecialchars($forum['description']) ?></p>
                    </div>
                <?php endforeach; ?>
            </div>
        <?php else: ?>
            <p>No forums available.</p>
        <?php endif; ?>
    </div>

    <div class="recent-activity">
        <h2>Recent Threads</h2>
        <?php if (!empty($recent_threads)): ?>
            <ul class="thread-list">
                <?php foreach ($recent_threads as $thread): ?>
                    <li>
                        <a href="thread.php?id=<?= $thread['id'] ?>"><?= htmlspecialchars($thread['title']) ?></a>
                        <span class="thread-meta">
                            by <?= htmlspecialchars($thread['author']) ?> 
                            | <?= getTimeAgo($thread['created_at']) ?>
                        </span>
                    </li>
                <?php endforeach; ?>
            </ul>
        <?php else: ?>
            <p>No recent threads.</p>
        <?php endif; ?>
    </div>
</div>