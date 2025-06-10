<?php
session_start();
require_once '../config/database.php';
require_once '../classes/Invite.php';

$invite = new Invite($pdo);

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (isset($_POST['send_invite'])) {
        $email = $_POST['email'];
        $result = $invite->sendInvite($email);
        if ($result) {
            $_SESSION['message'] = "Invitation sent to $email.";
        } else {
            $_SESSION['error'] = "Failed to send invitation.";
        }
    }

    if (isset($_POST['delete_invite'])) {
        $inviteId = $_POST['invite_id'];
        $result = $invite->deleteInvite($inviteId);
        if ($result) {
            $_SESSION['message'] = "Invitation deleted.";
        } else {
            $_SESSION['error'] = "Failed to delete invitation.";
        }
    }
}

$invites = $invite->getInvites();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Manage Invites</title>
    <link rel="stylesheet" href="../assets/css/style.css">
</head>
<body>
    <?php include '../includes/header.php'; ?>
    <div class="container">
        <h1>Manage Invites</h1>
        <?php if (isset($_SESSION['message'])): ?>
            <div class="alert alert-success"><?= $_SESSION['message']; unset($_SESSION['message']); ?></div>
        <?php endif; ?>
        <?php if (isset($_SESSION['error'])): ?>
            <div class="alert alert-danger"><?= $_SESSION['error']; unset($_SESSION['error']); ?></div>
        <?php endif; ?>

        <form method="POST" action="">
            <input type="email" name="email" placeholder="Enter email to invite" required>
            <button type="submit" name="send_invite">Send Invite</button>
        </form>

        <h2>Pending Invites</h2>
        <table>
            <thead>
                <tr>
                    <th>Email</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($invites as $invite): ?>
                    <tr>
                        <td><?= htmlspecialchars($invite['email']); ?></td>
                        <td>
                            <form method="POST" action="">
                                <input type="hidden" name="invite_id" value="<?= $invite['id']; ?>">
                                <button type="submit" name="delete_invite">Delete</button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <?php include '../includes/footer.php'; ?>
</body>
</html>