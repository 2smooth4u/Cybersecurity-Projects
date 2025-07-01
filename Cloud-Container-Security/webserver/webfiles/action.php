<?php
// Database credentials
$servername = "u5645801_csvs_dbserver_c";  // Use container name as hostname
$username = "root";
$password = "CorrectHorseBatteryStaple";
$database = "csvs23db";

// Connect securely using mysqli
$conn = new mysqli($servername, $username, $password, $database);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . htmlspecialchars($conn->connect_error));
}

// Sanitize input
$fullname = htmlspecialchars(trim($_POST['fullname'] ?? ''), ENT_QUOTES, 'UTF-8');
$suggestion = htmlspecialchars(trim($_POST['suggestion'] ?? ''), ENT_QUOTES, 'UTF-8');

// Validate input
if (!empty($fullname) && !empty($suggestion)) {
    $stmt = $conn->prepare("INSERT INTO suggestions (fullname, suggestion) VALUES (?, ?)");
    if ($stmt) {
        $stmt->bind_param("ss", $fullname, $suggestion);
        $stmt->execute();
        echo "<p>Thank you for your feedback!</p>";
        $stmt->close();
    } else {
        echo "<p>Database error: " . htmlspecialchars($conn->error) . "</p>";
    }
} else {
    echo "<p>Both fields are required.</p>";
}

$conn->close();
?>

