<?php
// Project: Sentinel-AI Forensic Terminal
// File: index.php (Main Academic Entry Point)
// Purpose: Main security command center home page with dynamic logs counter statistics

// Connect local database configuration setups
require_once('config/db_connect.php'); 

// Fetch quick running counter numbers from mysql threat tables
$query_all = mysqli_query($conn, "SELECT COUNT(*) as total FROM threat_logs");
$data_all = mysqli_fetch_assoc($query_all);
$total_scans = $data_all['total'] ?? 0;

$query_blocked = mysqli_query($conn, "SELECT COUNT(*) as blocked FROM threat_logs WHERE risk_score >= 60");
$data_blocked = mysqli_fetch_assoc($query_blocked);
$total_blocked = $data_blocked['blocked'] ?? 0;
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="assets/css/style.css">
    <title>Sentinel-AI | Security Command Center</title>
    <style>
        /* Top Navigation Header Styling Rules */
        nav { display: flex; justify-content: center; gap: 30px; padding: 20px; background: #0f172a; border-bottom: 1px solid #1e293b; }
        nav a { text-decoration: none; color: #94a3b8; font-weight: 600; font-size: 0.85em; letter-spacing: 1px; transition: 0.3s; }
        nav a:hover { color: #38bdf8; }
        
        .main-body { max-width: 1200px; margin: 40px auto; padding: 0 20px; font-family: sans-serif; text-align: left; }
        
        /* Advanced Dynamic Status Counter Row Panels */
        .analytics-row { display: flex; gap: 20px; margin-bottom: 30px; }
        .counter-card { background: #1e293b; border: 1px solid #334155; padding: 20px; border-radius: 10px; flex: 1; }
        .counter-card h4 { margin: 0 0 8px 0; color: #94a3b8; font-size: 0.8em; text-transform: uppercase; letter-spacing: 0.5px; }
        .counter-card h2 { margin: 0; font-size: 2em; font-weight: bold; color: #f8fafc; }
        
        /* Central Operations Splitting Console */
        .workspace-grid { display: flex; gap: 20px; margin-bottom: 30px; }
        .left-panel { flex: 1.5; background: #111827; border: 1px solid #1e293b; padding: 35px; border-radius: 12px; }
        .right-panel { flex: 1; background: #0b1329; border: 1px solid #1e293b; padding: 25px; border-radius: 12px; }
        
        /* New Executive Module Navigation Buttons Launcher */
        .action-launcher-box { display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px; margin-top: 30px; }
        .btn-launch { 
            background: #1e293b; border: 1px solid #334155; padding: 18px; border-radius: 8px; 
            text-decoration: none; display: block; transition: all 0.2s ease; 
        }
        .btn-launch:hover { border-color: #38bdf8; background: #151f32; transform: translateY(-2px); }
        .btn-launch h4 { margin: 0 0 5px 0; color: #38bdf8; font-size: 1em; }
        .btn-launch p { margin: 0; color: #94a3b8; font-size: 0.8em; line-height: 1.4; }
        
        /* Live Activity Stream Terminal Ticker styling */
        .terminal-feed-shell { background: #020617; border: 1px solid #1e293b; padding: 15px; border-radius: 6px; font-family: monospace; font-size: 0.85em; max-height: 220px; overflow-y: auto; }
        .feed-item { margin-bottom: 10px; border-bottom: 1px dashed #1e293b; padding-bottom: 6px; line-height: 1.4; }
    </style>
</head>
<body style="background-color: #0f172a; margin: 0; padding: 0;">

    <nav>
        <a href="index.php">COMMAND CENTER</a>
        <a href="public/scanner.php">THREAT SCANNER</a>
        <a href="public/cyber-laws.php">CYBER LAWS</a>
        <a href="admin/dashboard.php">ADMIN AUDIT LOGS</a>
    </nav>

    <div class="main-body">
        
        <div class="analytics-row">
            <div class="counter-card" style="border-left: 4px solid #38bdf8;">
                <h4>Total Captured Streams</h4>
                <h2><?php echo $total_scans; ?> Records</h2>
            </div>
            <div class="counter-card" style="border-left: 4px solid #ef4444;">
                <h4>Payload Exploit Blocks</h4>
                <h2><?php echo $total_blocked; ?> Alerts</h2>
            </div>
            <div class="counter-card" style="border-left: 4px solid #10b981;">
                <h4>System Security Status</h4>
                <h2 style="color: #10b981;">HARDENED RUNNING</h2>
            </div>
        </div>

        <div class="workspace-grid">
            
            <div class="left-panel">
                <span style="background: rgba(56, 189, 248, 0.1); color: #38bdf8; padding: 4px 10px; border-radius: 4px; font-size: 0.7em; font-weight: bold; text-transform: uppercase;">
                    System Overview Panel
                </span>
                <h1 style="color: #f8fafc; font-size: 2.3em; margin: 15px 0 10px 0; letter-spacing: -0.5px;">Sentinel-AI Security Framework</h1>
                <p style="color: #94a3b8; font-size: 1em; margin: 0 0 20px 0; line-height: 1.6;">
                    Heuristic pattern intelligence database mapped against statutory Indian cyber law boundaries. Enter data tokens via the scanner tool to record live forensic logs.
                </p>
                
                <hr style="border: 0; border-top: 1px solid #1e293b; margin: 25px 0;">

                <h3 style="color: #cbd5e1; font-size: 1.1em; margin: 0 0 15px 0;">Initialize Core Security Operations</h3>
                
                <div class="action-launcher-box">
                    <a href="public/scanner.php" class="btn-launch">
                        <h4>→ Deploy Threat Scanner</h4>
                        <p>Analyze target input tokens for nested obfuscated text layers, cURL redirects, and injection payloads.</p>
                    </a>
                    <a href="public/cyber-laws.php" class="btn-launch">
                        <h4>→ Open Cyber Jurisprudence</h4>
                        <p>Review system validation controls mapped against legal clauses of the Information Technology Act 2000.</p>
                    </a>
                    <a href="admin/dashboard.php" class="btn-launch">
                        <h4>→ Access Admin Panel Control</h4>
                        <p>Examine active database log entities, compile dynamic forensic PDF records, and audit raw telemetry indices.</p>
                    </a>
                    <a href="public/bomb.php" class="btn-launch" target="_blank" style="border-left: 3px solid #f59e0b;">
                        <h4>→ Simulation Tool (Redirect Bomb)</h4>
                        <p>Execute local loop script variables to test sniffer threshold protection barriers in safe testing space.</p>
                    </a>
                </div>
            </div>

            <div class="right-panel">
                <h4 style="color: #f59e0b; margin: 0 0 15px 0; text-transform: uppercase; font-size: 12px; border-bottom: 1px solid #1e293b; padding-bottom: 8px;">
                    Live Threat Feed Terminal Simulation
                </h4>
                
                <div class="terminal-feed-shell">
                    <?php
                    // Fetch latest 4 scan tracks from mysql to draw the interface feeds loop
                    $sql_get_feed = "SELECT user_input, risk_score, audit_id FROM threat_logs ORDER BY id DESC LIMIT 4";
                    $feed_result = mysqli_query($conn, $sql_get_feed);
                    
                    if (mysqli_num_rows($feed_result) > 0) {
                        while($feed_row = mysqli_fetch_assoc($feed_result)) {
                            $feed_score = $feed_row['risk_score'];
                            $feed_color = ($feed_score >= 60) ? '#ef4444' : (($feed_score >= 35) ? '#f59e0b' : '#10b981');
                            
                            echo "<div class='feed-item'>
                                    <span style='color: #64748b;'>[Track ID: " . $feed_row['audit_id'] . "]</span><br>
                                    <span style='color: #38bdf8;'>Data:</span> <code style='color: #cbd5e1; font-size:11px;'>" . htmlspecialchars(substr($feed_row['user_input'], 0, 35)) . "...</code><br>
                                    <span style='color: #94a3b8;'>Verdict Index:</span> <strong style='color: " . $feed_color . ";'>" . $feed_score . "% Risk</strong>
                                  </div>";
                        }
                    } else {
                        echo "<div style='color: #64748b; padding-top: 20px; text-align: center;'>No execution histories logged inside MySQL database tables.</div>";
                    }
                    ?>
                </div>

                <div style="margin-top: 20px; background: rgba(30, 41, 59, 0.3); padding: 15px; border-radius: 6px; border: 1px solid #1e293b;">
                    <span style="color: #94a3b8; font-size: 11px; display: block; line-height: 1.5;">
                        <strong>Academic Project Architecture:</strong> Built using clean PHP, procedural MySQLi storage drivers, and native canvas styles. Data structure verification handles telemetry parsing processes locally.
                    </span>
                </div>
            </div>

        </div>
    </div>

    <footer style="text-align: center; margin-top: 50px; color: #475569; font-size: 0.8em; padding-bottom: 40px;">
        &copy; 2026 Sentinel-AI Security Dashboard | Shalom Kumar BCA Project Final | ISBM University
    </footer>

</body>
</html>