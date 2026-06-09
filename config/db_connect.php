<?php
// Project: Sentinel-AI Forensic Terminal
// File: db_connect.php (Database Connection Script)
// Purpose: Establish local connection to MySQL Server to store scanned threat records

// Local database credentials setup
$server_host = "localhost";
$db_username = "root";
$db_password = "";
$database_name = "sentinel_db";

// Connecting to mysql server using regular procedural function
$conn = mysqli_connect($server_host, $db_username, $db_password, $database_name);

// Connectivity check: check if database connection is successful or has error
if (!$conn) {
    // Stop the script execution and show connection fail error
    die("CRITICAL SYSTEM ERROR: Database handshake failed. " . mysqli_connect_error());
}

// Set connection charset properties to support advanced character tracking scans
mysqli_set_charset($conn, "utf8mb4");

// Note: Connection successfully established, database is ready to save logs.
?>