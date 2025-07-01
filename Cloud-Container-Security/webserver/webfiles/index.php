<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Suggestion Box</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
  <form action="action.php" method="POST">
    <label for="fullname">Full Name:</label>
    <input type="text" name="fullname" required>
    <label for="suggestion">Suggestion:</label>
    <textarea name="suggestion" required></textarea>
    <button type="submit">Submit</button>
  </form>

  <h2>Previous Suggestions</h2>
  <ul>
    <?php
    // Connect to database
    $servername = "u5645801_csvs_dbserver_c";
    $username = "root";
    $password = "CorrectHorseBatteryStaple";
    $database = "csvs23db";

    $conn = new mysqli($servername, $username, $password, $database);

    // Check connection
    if ($conn->connect_error) {
        echo "<li>Connection failed: " . htmlspecialchars($conn->connect_error) . "</li>";
    } else {
        $result = $conn->query("SELECT fullname, suggestion FROM suggestions ORDER BY id DESC");

        if ($result && $result->num_rows > 0) {
            while ($row = $result->fetch_assoc()) {
                $name = htmlspecialchars($row['fullname'], ENT_QUOTES, 'UTF-8');
                $text = htmlspecialchars($row['suggestion'], ENT_QUOTES, 'UTF-8');
                echo "<li><strong>{$name}:</strong> {$text}</li>";
            }
        } else {
            echo "<li>No suggestions found.</li>";
        }

        $conn->close();
    }
    ?>
  </ul>
</body>
</html>

