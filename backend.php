<?php
session_start();
header('Content-Type: application/json'); // ✅ Ensures JSON output is properly parsed by JS

$conn = new mysqli("localhost", "root", "", "currency_db");
if ($conn->connect_error) {
    echo json_encode(['status' => 0, 'message' => 'Database connection failed']);
    exit;
}

$action = $_POST['action'] ?? '';

function sanitize($conn, $str) {
    return mysqli_real_escape_string($conn, trim($str));
}

if ($action == 'signup') {
    $username = sanitize($conn, $_POST['username']);
    $email = sanitize($conn, $_POST['email']);
    $password = password_hash($_POST['password'], PASSWORD_DEFAULT);

    $check = $conn->prepare("SELECT * FROM users WHERE username=? OR email=?");
    $check->bind_param("ss", $username, $email);
    $check->execute();
    $result = $check->get_result();

    if ($result->num_rows > 0) {
        echo json_encode(['status' => 0, 'message' => 'Username or Email already exists']);
    } else {
        $stmt = $conn->prepare("INSERT INTO users(username, email, password) VALUES (?, ?, ?)");
        $stmt->bind_param("sss", $username, $email, $password);
        $stmt->execute();
        echo json_encode(['status' => 1, 'message' => 'Signup successful']);
    }
    exit;
}

if ($action == 'login') {
    $username = sanitize($conn, $_POST['username']);
    $password = $_POST['password'];

    $stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $res = $stmt->get_result();

    if ($res->num_rows > 0) {
        $row = $res->fetch_assoc();
        if (password_verify($password, $row['password'])) {
            $_SESSION['user_id'] = $row['id'];
            $_SESSION['username'] = $row['username'];
            echo json_encode(['status' => 1, 'username' => $row['username']]);
        } else {
            echo json_encode(['status' => 0, 'message' => 'Incorrect password']);
        }
    } else {
        echo json_encode(['status' => 0, 'message' => 'User not found']);
    }
    exit;
}

if ($action == 'logout') {
    session_destroy();
    echo json_encode(['status' => 1]);
    exit;
}

if ($action == 'add_history') {
    if (!isset($_SESSION['user_id'])) {
        echo json_encode(['status' => 0, 'message' => 'Not logged in']);
        exit;
    }
    $user_id = $_SESSION['user_id'];
    $from = sanitize($conn, $_POST['from']);
    $to = sanitize($conn, $_POST['to']);
    $amount = floatval($_POST['amount']);
    $result = floatval($_POST['result']);

    $stmt = $conn->prepare("INSERT INTO history(user_id, from_currency, to_currency, amount, result) VALUES (?, ?, ?, ?, ?)");
    $stmt->bind_param("isssd", $user_id, $from, $to, $amount, $result);
    $stmt->execute();

    echo json_encode(['status' => 1]);
    exit;
}

if ($action == 'get_history') {
    if (!isset($_SESSION['user_id'])) {
        echo json_encode(['status' => 0]);
        exit;
    }
    $user_id = $_SESSION['user_id'];
    $stmt = $conn->prepare("SELECT * FROM history WHERE user_id = ? ORDER BY created_at DESC");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $res = $stmt->get_result();
    $data = [];
    while ($row = $res->fetch_assoc()) {
        $data[] = $row;
    }
    echo json_encode(['status' => 1, 'data' => $data]);
    exit;
}

if ($action == 'delete_history') {
    if (!isset($_SESSION['user_id'])) {
        echo json_encode(['status' => 0]);
        exit;
    }
    $id = intval($_POST['id']);
    $user_id = $_SESSION['user_id'];
    $stmt = $conn->prepare("DELETE FROM history WHERE id = ? AND user_id = ?");
    $stmt->bind_param("ii", $id, $user_id);
    $stmt->execute();

    echo json_encode(['status' => 1]);
    exit;
}
?>
