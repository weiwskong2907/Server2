<?php
class Invite {
    private $db;

    public function __construct($database) {
        $this->db = $database;
    }

    public function createInvite($email) {
        $stmt = $this->db->prepare("INSERT INTO invites (email, created_at) VALUES (:email, NOW())");
        $stmt->bindParam(':email', $email);
        return $stmt->execute();
    }

    public function getInvites() {
        $stmt = $this->db->query("SELECT * FROM invites");
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function deleteInvite($id) {
        $stmt = $this->db->prepare("DELETE FROM invites WHERE id = :id");
        $stmt->bindParam(':id', $id);
        return $stmt->execute();
    }

    public function sendInviteEmail($email) {
        // Code to send email invitation
        // This is intentionally left blank for now
    }
}
?>