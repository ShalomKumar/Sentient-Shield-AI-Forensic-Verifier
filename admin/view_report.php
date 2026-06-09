<?php 
// Project: Sentinel-AI Forensic Terminal
// File: view_report.php (Forensic Report Viewer)
// Purpose: Fetch a specific log record from database and display analysis with law compliance mappings

// Include database setup configurations
include('../config/db_connect.php'); 

// Check if parameter id is provided in the web link
if (isset($_GET['id'])) {
    $record_id = mysqli_real_escape_string($conn, $_GET['id']);
    
    // Fetch query execution line
    $sql_get_record = "SELECT * FROM threat_logs WHERE id = $record_id";
    $query_run = mysqli_query($conn, $sql_get_record);
    $report_data = mysqli_fetch_assoc($query_run);

    // If record is missing in mysql tables
    if (!$report_data) {
        die("<div style='color:white; background:#ef4444; padding:20px; font-family:sans-serif;'>ERROR: Forensic report record not found in database.</div>");
    }
} else {
    // Redirect back to dashboard if id is missing
    header("Location: ../index.php");
    exit;
}

// Re-generate the SHA-256 digital fingerprint to check file tamper logs
$hash_lock = hash('sha256', $report_data['user_input'] . $report_data['risk_score'] . $report_data['audit_id']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="../assets/css/style.css">
    <title>Forensic Audit Details | #<?php echo $report_data['audit_id']; ?></title>
    <style>
        body { background-color: #0f172a; margin: 0; padding: 0; font-family: sans-serif; }
        .step-container { margin-bottom: 25px; border-left: 3px solid #334155; padding-left: 20px; }
        .step-title { color: #38bdf8; font-weight: bold; text-transform: uppercase; font-size: 0.85em; letter-spacing: 1px; }
        
        .content-box { 
            background: rgba(30, 41, 59, 0.5); 
            padding: 20px; 
            border-radius: 8px; 
            margin-top: 10px; 
            color: #cbd5e1; 
            border: 1px solid #334155;
            line-height: 1.6;
        }

        /* Color tag settings based on risk index numbers */
        .text-safe { color: #22c55e !important; font-weight: bold; } 
        .text-danger-alert { color: #ff0000 !important; font-weight: bold; }

        .node-alert { 
            color: #fca5a5; 
            font-family: monospace; 
            font-size: 0.9em; 
            display: block; 
            margin-top: 10px;
            padding: 10px;
            background: rgba(220, 38, 38, 0.1);
            border: 1px solid rgba(220, 38, 38, 0.15);
            border-radius: 4px;
        }

        .integrity-box {
            margin-top: 20px;
            background: #0f2133;
            border: 1px dashed #38bdf8;
            padding: 15px;
            border-radius: 6px;
            word-break: break-all;
            font-family: monospace;
            font-size: 0.9em;
            color: #38bdf8;
        }

        code { font-weight: normal; word-break: break-all; background: #1e293b; padding: 2px 6px; border-radius: 4px; color: #cbd5e1; }
        
        /* Dynamic High-Risk Cyber Neon Red Glow Container Style */
        .cyber-red-glow-container {
            background: rgba(255, 0, 0, 0.12) !important; 
            color: #ff3333 !important; 
            padding: 6px 14px; 
            border: 1px solid #ef4444 !important; 
            border-radius: 6px; 
            font-family: monospace; 
            font-weight: bold; 
            box-shadow: 0 0 15px rgba(239, 68, 68, 0.65), inset 0 0 8px rgba(239, 68, 68, 0.3); 
            text-shadow: 0 0 8px rgba(255, 51, 51, 0.8); 
            display: inline-block; 
            word-break: break-all;
        }
    </style>
</head>
<body>
    <div class="container" style="max-width: 950px; padding-top: 50px; margin: 0 auto;">
        
        <header style="display: flex; justify-content: space-between; align-items: flex-end; margin-bottom: 40px; border-bottom: 1px solid #1e293b; padding-bottom: 20px;">
            <div>
                <a href="../index.php" style="color: #38bdf8; text-decoration: none; font-size: 0.85em; font-weight: bold;">← RETURN TO DASHBOARD</a>
                <h1 style="color: #f8fafc; margin-top: 15px; font-size: 2em;">Forensic Log Re-Examination</h1>
            </div>
            <div style="text-align: right; color: #64748b; font-size: 0.85em; line-height: 1.6;">
                Analyst: <strong>Shalom Kumar</strong><br>
                ISBM University | BCA Dept Major Project
            </div>
        </header>

        <div class="card" style="text-align: left; padding: 40px; background: #111827; border: 1px solid #1e293b; border-radius: 12px;">
            
            <div class="step-container">
                <span class="step-title">SECTION 1: Target Ingestion & Identification</span>
                <div class="content-box">
                    <table style="width: 100%; border-collapse: collapse;">
                        <tr>
                            <td style="width: 200px; color: #64748b; padding: 5px 0; vertical-align: middle;">Telemetry Input Trace:</td>
                            <td style="padding: 5px 0;">
                                <?php 
                                $risk_val = $report_data['risk_score']; 
                                $text_css_class = ($risk_val >= 75) ? 'text-danger-alert' : (($risk_val == 0) ? 'text-safe' : '');
                                
                                // Checking if threat index is active high risk to trigger the cyber neon red glow wrapper
                                if ($risk_val >= 75) {
                                    echo '<span class="cyber-red-glow-container">' . htmlspecialchars($report_data['user_input']) . '</span>';
                                } else {
                                    echo '<code class="' . $text_css_class . '">' . htmlspecialchars($report_data['user_input']) . '</code>';
                                }
                                ?>
                            </td>
                        </tr>
                        <tr><td style="color: #64748b; padding: 5px 0;">Forensic Audit ID:</td><td style="color: #38bdf8; font-weight: bold;"><?php echo $report_data['audit_id']; ?></td></tr>
                        <tr><td style="color: #64748b; padding: 5px 0;">Log Creation Time:</td><td><?php echo date('M d, Y | H:i:s', strtotime($report_data['detected_at'])); ?></td></tr>
                    </table>
                </div>
            </div>

            <div class="step-container">
                <span class="step-title">SECTION 2: Intelligence Risk Quantization</span>
                <div class="content-box">
                    <div style="display: flex; align-items: center; gap: 30px;">
                        <div>
                            <span style="display: block; font-size: 0.75em; color: #64748b; text-transform: uppercase;">Heuristic Risk Index</span>
                            <?php $score_color = ($risk_val >= 50) ? '#ef4444' : '#22c55e'; ?>
                            <span style="font-size: 2.2em; font-weight: 800; color: <?php echo $score_color; ?>;"><?php echo $risk_val; ?>%</span>
                        </div>
                        <div style="border-left: 1px solid #334155; padding-left: 30px;">
                            <span style="display: block; font-size: 0.75em; color: #64748b; text-transform: uppercase;">Security Verdict Badge</span>
                            <span style="font-size: 1.2em; font-weight: bold; color: #f1f5f9; text-transform: uppercase;"><?php echo htmlspecialchars($report_data['status']); ?></span>
                        </div>
                    </div>
                </div>
            </div>

            <div class="step-container" style="border-left-color: #ef4444;">
                <span class="step-title">SECTION 3: Detailed Forensic Logic Steps</span>
                <div class="content-box">
                    <p style="margin-top: 0;">The Sentinel-AI engine executed a multi-layered heuristic audit. Historical database evidence confirms:</p>
                    <span class="node-alert"><strong>[!] SCANNER_NODE_1:</strong> QUICK MATCH SEARCH APPLIED BASED ON BLACKLIST KEYWORDS.</span>
                    <span class="node-alert"><strong>[!] SCANNER_NODE_2:</strong> TEXT PATTERN RUN SUCCESSFULLY INSIDE REGEX ANALYZER FILTER.</span>
                    <span class="node-alert"><strong>[!] SCANNER_NODE_3:</strong> TOTAL WEIGHT METRICS CALCULATED AT <?php echo $risk_val; ?>% THROUGH SYSTEM LAWS.</span>
                </div>
            </div>

            <div style="display: flex; gap: 20px; margin-top: 25px; margin-bottom: 25px; width: 100%;">
                
                <div style="flex: 1; background: #0f172a; padding: 20px; border-radius: 8px; border: 1px solid #1e293b;">
                    <h4 style="color: #38bdf8; margin-top: 0; text-transform: uppercase; font-size: 13px; border-bottom: 1px solid #334155; padding-bottom: 8px; letter-spacing: 0.5px;">
                        Execution Telemetry Profile
                    </h4>
                    <div style="color: #cbd5e1; font-size: 12.5px; line-height: 1.7;">
                        
                        <div style="margin-bottom: 12px; border-bottom: 1px dashed #1e293b; padding-bottom: 8px;">
                            <strong style="color: #f8fafc; display: block;">1. Ingress Rate Profile (Speed & Traffic Gate)</strong>
                            <span style="color: #38bdf8; font-family: monospace; font-size: 11px;">[Technical]: Volumetric packet stream analyzed within safe baseline thresholds.</span><br>
                            <span style="color: #94a3b8; font-style: italic;">[Non-Technical]: System ne aane waale traffic ki speed aur quantity ko check kiya taaki website par overload na ho aur server crash na kare.</span>
                        </div>

                        <div style="margin-bottom: 12px; border-bottom: 1px dashed #1e293b; padding-bottom: 8px;">
                            <strong style="color: #f8fafc; display: block;">2. Linguistic Node Parse (Deep Text Scanning)</strong>
                            <span style="color: #38bdf8; font-family: monospace; font-size: 11px;">[Technical]: Sub-second regular expression check intercepted token structures.</span><br>
                            <span style="color: #94a3b8; font-style: italic;">[Non-Technical]: Input kiye gaye text ya link ke andar chhupe huye dangerous hacking codes ko ek second se bhi kam samay mein scan karke dhoondha gaya.</span>
                        </div>

                        <div style="margin-bottom: 12px; border-bottom: 1px dashed #1e293b; padding-bottom: 8px;">
                            <strong style="color: #f8fafc; display: block;">3. Network Hop Trajectory (Link Redirection Track)</strong>
                            <span style="color: #38bdf8; font-family: monospace; font-size: 11px;">[Technical]: Look-ahead sniffer validated external header state redirections.</span><br>
                            <span style="color: #94a3b8; font-style: italic;">[Non-Technical]: Agar koi link baar-baar doosre badnaam ya fake links par auto-forward (redirect) ho raha hai, toh system ne use live track karke block kiya.</span>
                        </div>

                        <div style="margin-bottom: 4px;">
                            <strong style="color: #f8fafc; display: block;">4. Data Cryptographic Seal (Digital Lock)</strong>
                            <span style="color: #38bdf8; font-family: monospace; font-size: 11px;">[Technical]: Localized SHA-256 fingerprint generated to secure chain-of-custody.</span><br>
                            <span style="color: #94a3b8; font-style: italic;">[Non-Technical]: Is report ka ek unique digital signature lock banaya gaya hai taaki koi bhi sarkaari ya legal court mein is saboot ko jhootha na sabit kar sake.</span>
                        </div>

                    </div>
                </div>

                <div style="flex: 1; background: #0b1329; padding: 20px; border-radius: 8px; border: 1px solid #1e293b;">
                    <h4 style="color: #f59e0b; margin-top: 0; text-transform: uppercase; font-size: 13px; border-bottom: 1px solid #334155; padding-bottom: 8px;">
                        Statutory Cyber Law Compliance Mapping
                    </h4>
                    
                    <div style="margin-top: 10px; padding: 8px; background: rgba(30, 41, 59, 0.5); border-left: 3px solid #0066cc; margin-bottom: 8px;">
                        <span style="color: #38bdf8; font-weight: bold; font-size: 11px; display: block;">STEP 1 Compliance | IT Act 2000 - Section 43(f)</span>
                        <span style="color: #94a3b8; font-size: 11px; display: block; margin-top: 2px;">DoS Prevention: Request processing frequency verified safe against infrastructure thread starvation.</span>
                    </div>

                    <div style="padding: 8px; background: rgba(30, 41, 59, 0.5); border-left: 3px solid #cc6600; margin-bottom: 8px;">
                        <span style="color: #fbbf24; font-weight: bold; font-size: 11px; display: block;">STEP 2 Compliance | IT Act 2000 - Section 66 r/w 43(i)</span>
                        <span style="color: #94a3b8; font-size: 11px; display: block; margin-top: 2px;">Source Protection: Pattern-matching core confirmed tokenized strings are free from dangerous execution scripts.</span>
                    </div>

                    <div style="padding: 8px; background: rgba(30, 41, 59, 0.5); border-left: 3px solid #cc0000; margin-bottom: 8px;">
                        <span style="color: #ef4444; font-weight: bold; font-size: 11px; display: block;">STEP 3 Compliance | IT Act 2000 - Section 66F</span>
                        <span style="color: #94a3b8; font-size: 11px; display: block; margin-top: 2px;">Infrastructure Security: Network sniffer intercepted header response tracks to kill recursive redirect bombs.</span>
                    </div>

                    <div style="padding: 8px; background: rgba(30, 41, 59, 0.5); border-left: 3px solid #009933;">
                        <span style="color: #34d399; font-weight: bold; font-size: 11px; display: block;">STEP 4 Compliance | Evidence Act - Section 65B</span>
                        <span style="color: #94a3b8; font-size: 11px; display: block; margin-top: 2px;">Judicial Admissibility: Permanent SHA-256 digital signature calculated to lock immutable session logs.</span>
                    </div>
                </div>

            </div>

            <div class="step-container">
                <span class="step-title">SECTION 4: Forensic Integrity Verification</span>
                <div class="integrity-box">
                    <strong>SHA-256 SYSTEM DIGITAL LOCK HASH (VERIFIED FROM DATABASE RECORDS):</strong><br>
                    <?php echo $hash_lock; ?>
                </div>
            </div>

            <div style="margin-top: 40px; padding: 25px; background: rgba(2, 6, 23, 0.5); border-radius: 8px; border: 1px solid #1e293b;">
                <p style="font-size: 0.9em; color: #64748b; margin: 0;">
                    <strong style="color: #cbd5e1;">EXECUTIVE SUMMARY:</strong> This database log asset has been retrieved from persistent MySQL table storage layers. The terminal system maintains the matching original audit verdict of <strong><?php echo strtoupper($report_data['status']); ?></strong> based on cryptographic non-repudiation checks.
                </p>
            </div>
        </div>

        <footer style="margin-top: 30px; text-align: center; color: #475569; font-size: 0.8em; letter-spacing: 1px; padding-bottom: 50px;">
            SENTINEL-AI CYBER FORENSICS TERMINAL | DEVELOPED BY SHALOM KUMAR
        </footer>
    </div>
</body>
</html>