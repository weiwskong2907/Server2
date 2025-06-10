class Forum {
    private $db;

    public function __construct($database) {
        $this->db = $database;
    }

    public function createCategory($name, $description) {
        $stmt = $this->db->prepare("INSERT INTO categories (name, description) VALUES (:name, :description)");
        $stmt->bindParam(':name', $name);
        $stmt->bindParam(':description', $description);
        return $stmt->execute();
    }

    public function getCategories() {
        $stmt = $this->db->query("SELECT * FROM categories");
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function deleteCategory($id) {
        $stmt = $this->db->prepare("DELETE FROM categories WHERE id = :id");
        $stmt->bindParam(':id', $id);
        return $stmt->execute();
    }

    public function updateCategory($id, $name, $description) {
        $stmt = $this->db->prepare("UPDATE categories SET name = :name, description = :description WHERE id = :id");
        $stmt->bindParam(':id', $id);
        $stmt->bindParam(':name', $name);
        $stmt->bindParam(':description', $description);
        return $stmt->execute();
    }
}