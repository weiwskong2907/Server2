class Post {
    private $db;

    public function __construct($database) {
        $this->db = $database;
    }

    public function createPost($userId, $forumId, $title, $content) {
        $stmt = $this->db->prepare("INSERT INTO posts (user_id, forum_id, title, content, created_at) VALUES (:user_id, :forum_id, :title, :content, NOW())");
        $stmt->bindParam(':user_id', $userId);
        $stmt->bindParam(':forum_id', $forumId);
        $stmt->bindParam(':title', $title);
        $stmt->bindParam(':content', $content);
        return $stmt->execute();
    }

    public function editPost($postId, $title, $content) {
        $stmt = $this->db->prepare("UPDATE posts SET title = :title, content = :content WHERE id = :post_id");
        $stmt->bindParam(':post_id', $postId);
        $stmt->bindParam(':title', $title);
        $stmt->bindParam(':content', $content);
        return $stmt->execute();
    }

    public function deletePost($postId) {
        $stmt = $this->db->prepare("DELETE FROM posts WHERE id = :post_id");
        $stmt->bindParam(':post_id', $postId);
        return $stmt->execute();
    }

    public function getPost($postId) {
        $stmt = $this->db->prepare("SELECT * FROM posts WHERE id = :post_id");
        $stmt->bindParam(':post_id', $postId);
        $stmt->execute();
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    public function getPostsByForum($forumId) {
        $stmt = $this->db->prepare("SELECT * FROM posts WHERE forum_id = :forum_id ORDER BY created_at DESC");
        $stmt->bindParam(':forum_id', $forumId);
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
}