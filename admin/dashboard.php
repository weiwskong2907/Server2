<?php
session_start();
require_once '../config/config.php';
require_once '../includes/auth.php';
require_once '../includes/functions.php';require_once '../includes/functions.php';

// Check if the user is logged in and is an admin
if (!isLoggedIn() || !isAdmin()) {e login to view profiles', 'error');
    header('Location: ../pages/login.php');
    exit();
}$user_id = $_GET['id'] ?? $_SESSION['user_id'];

$stats = [
    'total_users' => count(getAllUsers()),
    'total_forums' => count(getAllForums()),
    'total_posts' => count(getRecentPosts(PHP_INT_MAX)),// Check if viewing own profile or has admin rights
    'recent_activities' => getSystemLogs(10)r_id == $_SESSION['user_id']) || isAdmin();
];

// Include header<!DOCTYPE html>
include '../includes/header.php';
?>
8">
<div class="container">content="width=device-width, initial-scale=1.0">
    <h1>Admin Dashboard</h1>$user['username']) ?></title>
    <div class="admin-actions">f="../assets/css/style.css">
        <a href="create-forum.php" class="btn btn-primary">New Forum</a>
        <a href="create-user.php" class="btn btn-secondary">New User</a>
    </div>
    <div class="stats-grid">
        <div class="stat-card">="container">
            <h3>Total Users</h3>e-header">
            <p class="stat-number"><?= $stats['total_users'] ?></p>
            <a href="manage-users.php" class="stat-link">View All Users</a>r['avatar_url']): ?>
        </div>      <img src="<?= htmlspecialchars($user['avatar_url']) ?>" alt="Profile Avatar">
        <div class="stat-card">      <?php else: ?>
            <h3>Total Forums</h3>s="default-avatar"><?= strtoupper(substr($user['username'], 0, 1)) ?></div>
            <p class="stat-number"><?= $stats['total_forums'] ?></p> ?>
            <a href="manage-forums.php" class="stat-link">View All Forums</a></div>
        </div>
        <div class="stat-card">
            <h3>Total Posts</h3>
            <p class="stat-number"><?= $stats['total_posts'] ?></p>   <p class="role-badge <?= $user['role'] ?>"><?= ucfirst($user['role']) ?></p>
            <a href="manage-posts.php" class="stat-link">View All Posts</a>      <p>Member since: <?= date('F j, Y', strtotime($user['created_at'])) ?></p>
        </div>      </div>
    </div>
       <?php if ($can_edit): ?>
    <div class="admin-section">class="profile-actions">
        <h2>Recent Activity</h2>file.php" class="btn btn-primary">Edit Profile</a>
        <div class="activity-table">              <?php if (isAdmin()): ?>                    <a href="../admin/manage-users.php?id=<?= $user['id'] ?>" class="btn btn-secondary">Manage User</a>
            <table>                <?php endif; ?>
                <thead>            </div>
                    <tr>            <?php endif; ?>
                        <th>Time</th>        </div>
                        <th>User</th>
                        <th>Action</th>        <div class="profile-content">
                        <th>Details</th>            <div class="profile-stats">
                    </tr>                <h2>Statistics</h2>
                </thead>                <div class="stats-grid">
                <tbody>                    <div class="stat-item">
                    <?php foreach ($stats['recent_activities'] as $activity): ?>                        <span class="stat-value"><?= $stats['post_count'] ?></span>
                        <tr>                        <span class="stat-label">Posts</span>
                            <td><?= date('Y-m-d H:i:s', strtotime($activity['timestamp'])) ?></td>                    </div>                    <div class="stat-item">
                            <td><?= htmlspecialchars($activity['username']) ?></td>                        <span class="stat-value"><?= $stats['topics_count'] ?></span>                        <span class="stat-label">Topics</span>
                            <td><?= htmlspecialchars($activity['action']) ?></td>                    </div>                    <div class="stat-item">                        <span class="stat-value"><?= $stats['reputation'] ?? 0 ?></span>                        <span class="stat-label">Reputation</span>
                            <td><?= htmlspecialchars($activity['details']) ?></td>                    </div>                </div>            </div>
                        </tr>
                    <?php endforeach; ?>            <div class="profile-bio">                <h2>About</h2>                <p><?= nl2br(htmlspecialchars($user['bio'] ?? 'No bio available.')) ?></p>
                </tbody>            </div>
            </table>            <div class="profile-activity">
        </div>                <h2>Recent Activity</h2>
    </div>                <?php if (!empty($recent_activity)): ?>                    <ul class="activity-list">
                        <?php foreach ($recent_activity as $activity): ?>
    <div class="admin-section">                            <li class="activity-item">                                <span class="activity-type"><?= ucfirst($activity['type']) ?></span>                                <span class="activity-content">                                    <?= htmlspecialchars($activity['description']) ?>                                </span>                                <span class="activity-date">                                    <?= date('M j, Y g:i a', strtotime($activity['created_at'])) ?>                                </span>                            </li>                        <?php endforeach; ?>                    </ul>                <?php else: ?>                    <p>No recent activity.</p>                <?php endif; ?>            </div>        </div>    </div>    <?php include '../includes/footer.php'; ?></body></html>
        <h2>Quick Actions</h2>
        <div class="quick-actions">
            <a href="backup.php" class="action-btn">Backup Database</a>
            <a href="cache.php" class="action-btn">Clear Cache</a>
            <a href="logs.php" class="action-btn">View Logs</a>
            <a href="settings.php" class="action-btn">System Settings</a>
        </div>
    </div>
</div>

<?php
// Include footer
include '../includes/footer.php';
?>
<script src="../assets/js/admin.js"></script>
</body>
</html>