class User {
    private $db;

    public function __construct($database) {
        $this->db = $database;
    }

    public function register($username, $password, $email) {
        // Hash the password
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
        
        // Prepare SQL statement
        $stmt = $this->db->prepare("INSERT INTO users (username, password, email) VALUES (:username, :password, :email)");
        $stmt->bindParam(':username', $username);
        $stmt->bindParam(':password', $hashedPassword);
        $stmt->bindParam(':email', $email);
        
        return $stmt->execute();
    }

    public function login($username, $password) {
        // Prepare SQL statement
        $stmt = $this->db->prepare("SELECT * FROM users WHERE username = :username");
        $stmt->bindParam(':username', $username);
        $stmt->execute();
        
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        // Verify password
        if ($user && password_verify($password, $user['password'])) {
            // Start session and set user data
            session_start();
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            return true;
        }
        
        return false;
    }

    public function getUserById($id) {
        $stmt = $this->db->prepare("SELECT * FROM users WHERE id = :id");
        $stmt->bindParam(':id', $id);
        $stmt->execute();
        
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    public function updateProfile($id, $username, $email) {
        $stmt = $this->db->prepare("UPDATE users SET username = :username, email = :email WHERE id = :id");
        $stmt->bindParam(':username', $username);
        $stmt->bindParam(':email', $email);
        $stmt->bindParam(':id', $id);
        
        return $stmt->execute();
    }

    public function deleteUser($id) {
        $stmt = $this->db->prepare("DELETE FROM users WHERE id = :id");
        $stmt->bindParam(':id', $id);
        
        return $stmt->execute();
    }
}