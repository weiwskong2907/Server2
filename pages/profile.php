<?php
session_start();
require_once '../config/config.php';
require_once '../includes/auth.php';
require_once '../includes/functions.php';

if (!isLoggedIn()) {
    redirectWithMessage('login.php', 'Please login to view profiles', 'error');
}

try {
    $user_id = filter_input(INPUT_GET, 'id', FILTER_SANITIZE_NUMBER_INT) ?? $_SESSION['user_id'];
    $user = getUserById($user_id);

    if (!$user) {
        throw new Exception('User not found');
    }

    $stats = getUserStatistics($user_id);
    $recent_activity = getUserActivity($user_id);
    $can_edit = ($user_id == $_SESSION['user_id']) || isAdmin();
} catch (Exception $e) {
    redirectWithMessage('index.php', $e->getMessage(), 'error');
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Profile - <?= htmlspecialchars($user['username']) ?></title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/timeago.js/4.0.2/timeago.min.js"></script>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css">
    <link rel="stylesheet" href="../assets/css/style.css">
    <link rel="stylesheet" href="../assets/css/profile.css">
    <script src="../assets/js/profile.js" defer></script>
    <meta name="csrf-token" content="<?= generateCSRFToken() ?>">
</head>
<body>
    <?php include '../includes/header.php'; ?>

    <div id="notifications" class="notifications-container"></div>

    <div class="container">
        <div class="profile-header">
            <div class="profile-avatar-wrapper">
                <div class="profile-avatar" id="profileAvatar">
                    <?php if ($user['avatar_url']): ?>
                        <img src="<?= htmlspecialchars($user['avatar_url']) ?>" alt="Profile Avatar">
                    <?php else: ?>
                        <div class="default-avatar"><?= strtoupper(substr($user['username'], 0, 1)) ?></div>
                    <?php endif; ?>
                </div>
                <?php if ($can_edit): ?>
                    <button class="avatar-upload-btn" id="avatarUploadBtn">
                        <i class="fas fa-camera"></i>
                    </button>
                    <input type="file" id="avatarInput" accept="image/*" hidden>
                <?php endif; ?>
            </div>

            <div class="profile-info">
                <h1><?= htmlspecialchars($user['username']) ?></h1>
                <p class="role-badge <?= $user['role'] ?>"><?= ucfirst($user['role']) ?></p>
                <p class="member-since">
                    <i class="fas fa-calendar-alt"></i>
                    Member since: <?= date('F j, Y', strtotime($user['created_at'])) ?>
                </p>
                <?php if ($user['last_seen']): ?>
                    <p class="last-seen">
                        <i class="fas fa-clock"></i>
                        Last seen: <?= getTimeAgo($user['last_seen']) ?>
                    </p>
                <?php endif; ?>
            </div>

            <?php if ($can_edit): ?>
            <div class="profile-actions">
                <a href="edit-profile.php" class="btn btn-primary">
                    <i class="fas fa-edit"></i> Edit Profile
                </a>
                <?php if (isAdmin() && $user_id != $_SESSION['user_id']): ?>
                    <a href="../admin/manage-users.php?id=<?= $user['id'] ?>" class="btn btn-secondary">
                        <i class="fas fa-user-cog"></i> Manage User
                    </a>
                <?php endif; ?>
            </div>
            <?php endif; ?>
        </div>

        <div class="profile-content">
            <?php try { ?>
                <div class="profile-sidebar">
                    <div class="profile-stats">
                        <h2><i class="fas fa-chart-bar"></i> Statistics</h2>
                        <div class="stats-grid">
                            <div class="stat-item">
                                <span class="stat-value" data-count="<?= $stats['post_count'] ?>">0</span>
                                <span class="stat-label">Posts</span>
                            </div>
                            <div class="stat-item">
                                <span class="stat-value" data-count="<?= $stats['topics_count'] ?>">0</span>
                                <span class="stat-label">Topics</span>
                            </div>
                            <div class="stat-item">
                                <span class="stat-value" data-count="<?= $stats['reputation'] ?? 0 ?>">0</span>
                                <span class="stat-label">Reputation</span>
                            </div>
                        </div>
                    </div>

                    <div class="profile-bio">
                        <h2><i class="fas fa-user"></i> About</h2>
                        <?php if ($can_edit): ?>
                            <div class="bio-edit" id="bioEdit">
                                <div class="bio-content" id="bioContent" data-original="<?= htmlspecialchars($user['bio'] ?? '') ?>">
                                    <?= nl2br(htmlspecialchars($user['bio'] ?? 'No bio available.')) ?>
                            </div>
                            <button class="btn btn-small" id="editBioBtn" title="Edit Bio">
                                <i class="fas fa-pencil-alt"></i>
                            </button>
                        </div>
                        <?php else: ?>
                            <p class="bio-content"><?= nl2br(htmlspecialchars($user['bio'] ?? 'No bio available.')) ?></p>
                        <?php endif; ?>
                    </div>
                </div>

                <div class="profile-main">
                    <div class="profile-activity">
                        <h2><i class="fas fa-history"></i> Recent Activity</h2>
                        <?php if (!empty($recent_activity)): ?>
                            <ul class="activity-list">
                                <?php foreach ($recent_activity as $activity): ?>
                                    <li class="activity-item">
                                        <span class="activity-type">
                                            <i class="fas fa-<?= getActivityIcon($activity['type']) ?>"></i>
                                            <?= ucfirst($activity['type']) ?>
                                        </span>
                                        <span class="activity-content">
                                            <?= htmlspecialchars($activity['description']) ?>
                                        </span>
                                        <span class="activity-date" title="<?= date('Y-m-d H:i:s', strtotime($activity['created_at'])) ?>">
                                            <?= getTimeAgo($activity['created_at']) ?>
                                        </span>
                                    </li>
                                <?php endforeach; ?>
                            </ul>
                            <?php if (count($recent_activity) >= 10): ?>
                                <button class="btn btn-load-more" id="loadMoreActivity" data-page="1">
                                    <span class="btn-text">Load More</span>
                                    <span class="btn-loader" style="display: none;">
                                        <i class="fas fa-spinner fa-spin"></i> Loading...
                                    </span>
                                </button>
                            <?php endif; ?>
                        <?php else: ?>
                            <p class="no-activity">No recent activity.</p>
                        <?php endif; ?>
                    </div>
                </div>
            <?php } catch (Exception $e) { ?>
                <div class="error-boundary">
                    <i class="fas fa-exclamation-circle"></i>
                    <p>Sorry, something went wrong while loading this section.</p>
                    <?php if (isAdmin()): ?>
                        <p class="error-details"><?= htmlspecialchars($e->getMessage()) ?></p>
                    <?php endif; ?>
                </div>
            <?php } ?>
        </div>
    </div>

    <?php include '../includes/footer.php'; ?>

    <!-- Modal for avatar upload -->
    <div class="modal" id="avatarModal" aria-hidden="true">
        <div class="modal-overlay"></div>
        <div class="modal-content" role="dialog" aria-labelledby="avatarModalTitle">
            <span class="close" aria-label="Close">&times;</span>
            <h2 id="avatarModalTitle">Update Profile Picture</h2>
            <div class="avatar-preview"></div>
            <div class="avatar-controls">
                <button class="btn btn-primary" id="saveAvatar">
                    <span class="btn-text">Save</span>
                    <span class="btn-loader" style="display: none;">
                        <i class="fas fa-spinner fa-spin"></i> Saving...
                    </span>
                </button>
                <button class="btn btn-secondary" id="cancelAvatar">Cancel</button>
            </div>
        </div>
    </div>
</body>
</html>