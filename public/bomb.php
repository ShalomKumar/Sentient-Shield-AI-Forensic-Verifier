<?php
// Project: Sentinel-AI Forensic Terminal
// File: bomb.php
// Purpose: Dummy file to test if our engine blocks infinite redirect loops (Redirect Bomb Test)

$redirect_target = "bomb.php"; // Apne hi page par baar-baar redirect karne ke liye
$time_delay = 0; // Bina kisi delay ke rapid loops chalane ke liye

// Test log check karne ke liye local file mein write kiya
file_put_contents("attack_log.txt", "Redirect Loop Test Triggered at: " . date('Y-m-d H:i:s') . "\n", FILE_APPEND);

// Native server header controls to run the loop execution
header("Refresh: $time_delay; url=$redirect_target");
header("Location: $redirect_target"); 
exit;
?>