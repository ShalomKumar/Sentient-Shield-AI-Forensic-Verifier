<?php
// Project: Sentinel-AI Forensic Terminal
// File: blacklist.php
// Purpose: List of bad words and hacking keywords for quick screening

// 1. Database of harmful strings and keywords
$sql_threats = array("' OR '1'='1'", "--", "UNION SELECT", "DROP TABLE", "SLEEP(", "BENCHMARK(", "INFORMATION_SCHEMA", "GROUP BY", "ORDER BY 100");
$xss_threats = array("<script>", "javascript:", "onerror=", "alert(", "String.fromCharCode", "window.location", "document.cookie", "confirm(");
$phishing_links = array("verify-account", "login-update", "secure-bank-login", "auth-confirm", "update-credential", "account-security-locked", "signin-verification");
$path_traversals = array("../../", "etc/passwd", "boot.ini", "php://filter", "http://", "ftp://");
$short_links = array("bit.ly/", "t.co/", "tinyurl.com/", "ngrok.io", "localtonet.com");

// 2. Simple function to check if input has any blacklisted word
function check_blacklist_match($user_input) {
    global $sql_threats, $xss_threats, $phishing_links, $path_traversals, $short_links;
    
    $user_input = strtolower($user_input);
    
    // Check for SQL Injection keywords
    foreach ($sql_threats as $bad_word) {
        if (strpos($user_input, strtolower($bad_word)) !== false) {
            return array('found' => true, 'type' => 'SQL Injection Pattern', 'word' => $bad_word);
        }
    }
    
    // Check for XSS script keywords
    foreach ($xss_threats as $bad_word) {
        if (strpos($user_input, strtolower($bad_word)) !== false) {
            return array('found' => true, 'type' => 'Cross-Site Scripting (XSS)', 'word' => $bad_word);
        }
    }
    
    // Check for Phishing text patterns
    foreach ($phishing_links as $bad_word) {
        if (strpos($user_input, strtolower($bad_word)) !== false) {
            return array('found' => true, 'type' => 'Phishing/Social Engineering', 'word' => $bad_word);
        }
    }
    
    // Check for Directory Path Traversal
    foreach ($path_traversals as $bad_word) {
        if (strpos($user_input, strtolower($bad_word)) !== false) {
            return array('found' => true, 'type' => 'Path Traversal Vulnerability', 'word' => $bad_word);
        }
    }
    
    // Check for Suspicious Short Links
    foreach ($short_links as $bad_word) {
        if (strpos($user_input, strtolower($bad_word)) !== false) {
            return array('found' => true, 'type' => 'Suspicious Redirect/Tunnel', 'word' => $bad_word);
        }
    }
    
    // If everything is clear
    return array('found' => false, 'type' => 'None', 'word' => '');
}
?>