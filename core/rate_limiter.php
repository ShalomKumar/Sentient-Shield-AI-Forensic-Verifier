<?php
/**
 * SENTINEL-AI: IP RATE LIMITING MODULE
 * Purpose: Prevents automated DoS attacks on the heuristic engine.
 */

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

function checkRateLimit() {
    $currentTime = time();
    $limit = 10;    // Maximum 10 scans allowed
    $window = 60;   // In 60 seconds (1 minute)

    // Initializing session variables for first-time users
    if (!isset($_SESSION['last_scan_time'])) {
        $_SESSION['last_scan_time'] = $currentTime;
        $_SESSION['scan_count'] = 1;
        return true;
    }

    // Checking the time window
    if ($currentTime - $_SESSION['last_scan_time'] < $window) {
        if ($_SESSION['scan_count'] >= $limit) {
            // Terminating the request if limit exceeded
            header('HTTP/1.1 429 Too Many Requests');
            die("<div style='color:#ef4444; background:rgba(239,68,68,0.1); padding:20px; border:1px solid #ef4444; border-radius:8px; font-family:sans-serif;'>
                <strong>[!] RATE LIMIT EXCEEDED:</strong> Too many requests from your IP. Please wait 60 seconds before the next security audit.
                </div>");
        }
        $_SESSION['scan_count']++;
    } else {
        // Resetting the window after 1 minute
        $_SESSION['last_scan_time'] = $currentTime;
        $_SESSION['scan_count'] = 1;
    }
    return true;
}
?>