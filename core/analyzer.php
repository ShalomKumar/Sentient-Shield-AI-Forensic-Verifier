<?php
// Project: Sentinel-AI Forensic Terminal
// File: analyzer.php
// Purpose: Core logic to scan inputs for threats like SQLi, XSS, and Obfuscation

function check_telemetry_threat($input_string) {
    $risk_score = 0;
    $reasons = array();
    $input_string = trim($input_string);
    
    // --- STEP 1: EMPTY INPUT CHECK ---
    if ($input_string == "") {
        return array(
            'score' => 0, 
            'status' => 'NULL_INPUT', 
            'reasons' => array('System Error: No input data provided for analysis.')
        );
    }

    // --- STEP 2: BRAND SPOOFING AND PHISHING CHECKS ---
    // Layer A: Subdomain spoofing lookups
    $check_brands = "/(google|facebook|instagram|amazon|apple|microsoft|netflix|isbm|paypal)\.com\.[a-z0-9-]+\.[a-z]{2,}/i";
    if (preg_match($check_brands, $input_string)) {
        $risk_score = $risk_score + 85;
        $reasons[] = "Detection: Fake Subdomain or Brand Impersonation Match.";
    }

    // Layer B: Visual deception lookups (Homograph characters swap)
    $fake_words = array('googIe', 'mIcrosoft', 'paypaI', 'facebaok', 'amazan'); 
    foreach ($fake_words as $word) {
        if (strpos($input_string, $word) !== false) {
            $risk_score = $risk_score + 90;
            $reasons[] = "Detection: Homograph Spoofing Pattern Found.";
            break;
        }
    }

    // Layer C: Social engineering dynamic tokens
    $bad_keywords = "/-login|-verify|-secure|-account|-signin|-update|-bank|-support/i";
    if (preg_match($bad_keywords, $input_string)) {
        $risk_score = $risk_score + 40;
        $reasons[] = "Detection: Suspicious Social Engineering Keyword Match.";
    }

    // --- STEP 3: OBFUSCATION AND HIDDEN TEXT CHECKS ---
    // Layer A: Base64 data injection match
    if (preg_match("/data:text\/html;base64,/i", $input_string)) {
        $risk_score = $risk_score + 95;
        $reasons[] = "Detection: Malicious Base64 Data URI Obfuscation Found.";
    }

    // Layer B: Checking base64 format strings
    if (preg_match('/^[a-zA-Z0-9\/\+=]+$/', $input_string) && strlen($input_string) > 25) {
        $plain_text = base64_decode($input_string, true);
        if ($plain_text) {
            if (preg_match('/(SELECT|script|UNION|<|>)/i', $plain_text)) {
                $risk_score = $risk_score + 85;
                $reasons[] = "Detection: Hidden Malicious Codes inside Base64 Payload.";
            }
        }
    }

    // Layer C: Invisible unicode text blocks
    if (preg_match("/[\x{200B}-\x{200D}\x{FEFF}]/u", $input_string)) {
        $risk_score = $risk_score + 80;
        $reasons[] = "Detection: Zero-Width Unicode Invisible Character Scan.";
    }

    // --- STEP 4: TRACKERS AND EXECUTABLES CHECKS ---
    // Layer A: Checking popular IP Loggers
    $bad_sites = array("/iplogger/i", "/grabify/i", "/blasze/i", "/psm/i", "/bitly/i");
    foreach ($bad_sites as $site) {
        if (preg_match($site, $input_string)) {
            $risk_score = $risk_score + 90;
            $reasons[] = "Detection: Traffic Routing to IP Logger or URL Tracker Link.";
            break;
        }
    }

    // Layer B: Dangerous system file downloads check
    if (preg_match("/\.(apk|exe|bat|sh|msi|php|py|vbs|js)$/i", $input_string)) {
        $risk_score = $risk_score + 75;
        $reasons[] = "Detection: Malicious Binary or Dangerous Executable Extension.";
    }

    // --- STEP 5: SQL INJECTION DATABASE CHECKS ---
    $sqli_rules = array(
        "/'|--|#|\/\|\\//", 
        "/\b(SELECT|UNION|INSERT|DELETE|DROP|TRUNCATE|SLEEP|BENCHMARK|DATABASE|USER)\b/i",
        "/\b(OR|AND|XOR|NOT)\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?/i",
        "/@@[a-z]+|INFORMATION_SCHEMA/i"
    );
    foreach ($sqli_rules as $pattern) {
        if (preg_match($pattern, $input_string)) {
            $risk_score = $risk_score + 90;
            $reasons[] = "Detection: SQL Injection Attempt detected.";
            break;
        }
    }

    // --- STEP 6: CROSS-SITE SCRIPTING (XSS) CHECKS ---
    $xss_rules = array(
        "/<script.?>.?<\/script>/is", 
        "/(onerror|onload|onclick|onmouseover)=/i", 
        "/alert\(|confirm\(|prompt\(/i"
    );
    foreach ($xss_rules as $pattern) {
        if (preg_match($pattern, $input_string)) {
            $risk_score = $risk_score + 85;
            $reasons[] = "Detection: Script Injection or XSS Payload Detected.";
            break;
        }
    }

    // --- STEP 7: EXTRA SYMBOLS SCAN (URL TUNNELING) ---
    $at_count = substr_count($input_string, '@');
    $ques_count = substr_count($input_string, '?');
    $dash_count = substr_count($input_string, '-');
    $eq_count = substr_count($input_string, '=');
    $total_symbols = $at_count + $ques_count + $dash_count + $eq_count;
    
    if ($total_symbols > 5 || strlen($input_string) > 120) {
        $risk_score = $risk_score + 50;
        $reasons[] = "Detection: Suspicious Symbol Density or Abnormal URL Length.";
    }

    // --- STEP 8: FINAL RISK SCORING AND BADGE STATUS ---
    if ($risk_score > 100) {
        $risk_score = 100;
    }

    if ($risk_score >= 85) {
        $verdict_badge = "BLOCKED (CRITICAL THREAT)";
    } else if ($risk_score >= 60) {
        $verdict_badge = "BLOCKED (HIGH RISK)";
    } else if ($risk_score >= 35) {
        $verdict_badge = "WARNING (SUSPICIOUS)";
    } else {
        $verdict_badge = "SAFE (VERIFIED)";
    }

    // Unique alpha-numeric audit identification code generation
    $random_bytes_data = random_bytes(4);
    $hex_string = bin2hex($random_bytes_data);
    $audit_unique_id = strtoupper($hex_string) . "-AUDIT";

    return array(
        'score' => $risk_score,
        'status' => $verdict_badge,
        'reasons' => array_unique($reasons),
        'forensic_id' => $audit_unique_id
    );
}
?>