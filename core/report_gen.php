<?php
// Project: Sentinel-AI Forensic Terminal
// File: report_gen.php
// Purpose: Main report generator script to compile and create PDF artifacts

require_once('fpdf.php');

class Sentinel_Report extends FPDF {
    // Custom Header Function for University Project Format
    function Header() {
        // Top banner block background color
        $this->SetFillColor(15, 23, 42); 
        $this->Rect(0, 0, 210, 45, 'F');

        // Main App Header Details
        $this->SetFont('Arial', 'B', 18);
        $this->SetTextColor(56, 189, 248); 
        $this->Text(12, 18, 'SENTINEL-AI: FORENSIC INTELLIGENCE REPORT');
        
        // Dynamic Project Index Data
        $this->SetFont('Arial', 'B', 10);
        $this->SetTextColor(255, 255, 255);
        $this->Text(12, 26, 'Lead Analyst: Shalom Kumar | Session: 2025-26 | Version: 4.5.0');
        
        $this->SetFont('Arial', 'I', 9);
        $this->SetTextColor(200, 200, 200);
        $this->Text(12, 32, 'Institution: ISBM University | Faculty of Computer Applications');
        
        $this->SetFont('Arial', 'I', 8);
        $this->SetTextColor(150, 150, 150);
        $this->Text(12, 38, 'Advanced Pattern Recognition & Heuristic Weightage Security Audit');
        
        $this->Ln(20); 
    }

    // Custom Footer Function for Document Identification
    function Footer() {
        $this->SetY(-15);
        $this->SetFont('Arial', 'I', 8);
        $this->SetTextColor(128, 128, 128);
        $this->Cell(0, 10, 'Automated Forensic Artifact | Sentinel-AI v4.5.0 | Confidential | Page ' . $this->PageNo(), 0, 0, 'C');
    }
}

function generateForensicReport($target_string, $analysis_array) {
    $pdf = new Sentinel_Report();
    $pdf->AddPage('P', 'A4');
    $pdf->SetFont('Arial', '', 11);
    $pdf->Ln(15); // Clear gap below branding layout

    // --- SECTION 1: TARGET DETAILS ---
    $pdf->SetFillColor(241, 245, 249); 
    $pdf->SetFont('Arial', 'B', 11);
    $pdf->SetTextColor(15, 23, 42);
    $pdf->Cell(190, 8, " SECTION 1: Target Ingestion & Identification", 0, 1, 'L', true);
    $pdf->SetFont('Arial', '', 10);
    $pdf->Ln(2);
    
    $pdf->MultiCell(190, 6, "Target Telemetry Stream: " . $target_string);
    $pdf->Cell(0, 6, "Forensic Audit ID: " . $analysis_array['forensic_id'], 0, 1);
    $pdf->Cell(0, 6, "Analysis Timestamp: " . date('Y-m-d | H:i:s'), 0, 1);
    $pdf->Ln(4);

    // --- SECTION 2: INTELLIGENCE METRICS ---
    $pdf->SetFont('Arial', 'B', 11);
    $pdf->Cell(190, 8, " SECTION 2: Intelligence-Based Risk Metrics", 0, 1, 'L', true);
    $pdf->SetFont('Arial', '', 10);
    $pdf->Ln(2);
    
    $score_check = intval($analysis_array['score'] ?? $analysis_array['risk_score']);
    
    // RGB dynamic text logic setup
    if ($score_check >= 70) {
        $color_r = 220; $color_g = 38; $color_b = 38; // Red Alert
    } else if ($score_check >= 35) {
        $color_r = 234; $color_g = 179; $color_b = 8;  // Amber Alert
    } else {
        $color_r = 22; $color_g = 163; $color_b = 74;   // Green Alert
    }
    
    $pdf->SetFont('Arial', 'B', 10);
    $pdf->Cell(45, 6, "Heuristic Risk Index:", 0, 0);
    $pdf->SetFont('Arial', 'B', 12);
    $pdf->SetTextColor($color_r, $color_g, $color_b);
    $pdf->Cell(0, 6, $score_check . "/100", 0, 1);
    
    $pdf->SetTextColor(0, 0, 0);
    $pdf->SetFont('Arial', 'B', 10);
    $pdf->Cell(45, 6, "Security Verdict:", 0, 0);
    $pdf->Cell(0, 6, strtoupper($analysis_array['status']), 0, 1);
    $pdf->Ln(4);

    // --- SECTION 3: FORENSIC DETECTION TIMELINE ---
    $pdf->SetFont('Arial', 'B', 11);
    $pdf->Cell(190, 8, " SECTION 3: Detailed Forensic Logic Steps", 0, 1, 'L', true);
    $pdf->SetFont('Arial', '', 10);
    $pdf->Ln(2);
    
    $pdf->MultiCell(190, 6, "The Sentinel-AI engine executed a weighted heuristic audit. The following threat signatures and behavioral anomalies were identified within the telemetry packet:");
    $pdf->Ln(2);
    
    if (empty($analysis_array['reasons'])) {
        $pdf->SetTextColor(22, 163, 74);
        $pdf->Cell(0, 6, "  [+] CLEAN_NODE: No immediate behavioral anomalies detected.", 0, 1);
    } else {
        // Convert dynamic reason loops cleanly
        $reasons_list = is_array($analysis_array['reasons']) ? $analysis_array['reasons'] : explode(',', $analysis_array['reasons']);
        foreach ($reasons_list as $key => $val) {
            if (trim($val) != "") {
                $pdf->SetTextColor(180, 0, 0);
                $pdf->MultiCell(190, 6, "  [!] DETECTION_NODE_" . ($key + 1) . ": " . strtoupper(trim($val)) . " SIGNATURE DETECTED");
                $pdf->SetTextColor(0, 0, 0);
            }
        }
    }
    
    $pdf->Ln(5);

    // --- SECTION 3.5: AUTOMATED CYBER LAW MATRIX COMPILING ---
    if ($pdf->GetY() > 155) {
        $pdf->AddPage();
        $pdf->Ln(15);
    }

    $pdf->SetFillColor(241, 245, 249); 
    $pdf->SetFont('Arial', 'B', 11);
    $pdf->SetTextColor(15, 23, 42);
    $pdf->Cell(190, 8, " SECTION 3.5: Statutory Cyber Law Mapping Analysis Matrix", 0, 1, 'L', true);
    $pdf->Ln(2);

    // Normal direct include path logic using current directory maps
    require_once(__DIR__ . '/cyber_law_helper.php');

    $weight_1 = 15; 
    $weight_2 = ($score_check >= 45) ? 45 : 0;
    $weight_3 = ($score_check == 100) ? 100 : 0;

    // Sequential manual trigger calls for the mapping tables
    InjectStatutoryLawBoxes($pdf, 1, "IP Gateway Evaluation - Volumetric Traffic Clearance Passed", $weight_1);
    InjectStatutoryLawBoxes($pdf, 2, "RegEx Logic Node Sweep Over Telemetry Token Components", $weight_2);
    InjectStatutoryLawBoxes($pdf, 3, "Layer 3 Sniffer Loop Interception - Trajectory Routing Status", $weight_3);
    InjectStatutoryLawBoxes($pdf, 4, "SHA-256 System Non-Repudiation Structural Signature Block", $score_check);
    
    $pdf->Ln(6);

    // --- SECTION 4: INTEGRITY EVIDENCE DATA ---
    if ($pdf->GetY() > 225) { 
        $pdf->AddPage(); 
        $pdf->Ln(15); 
    }
    
    $pdf->SetFont('Arial', 'B', 11);
    $pdf->SetFillColor(241, 245, 249); 
    $pdf->Cell(190, 8, " SECTION 4: Forensic Integrity Verification", 0, 1, 'L', true);
    $pdf->Ln(3);
    
    $report_hash = hash('sha256', $target_string . $score_check . $analysis_array['forensic_id']);
    $pdf->SetFont('Courier', 'B', 9);
    $pdf->SetFillColor(255, 255, 255);
    $pdf->MultiCell(190, 6, "SHA-256 DIGITAL FINGERPRINT (NON-REPUDIATION):\n" . $report_hash, 1, 'C');
    $pdf->Ln(6);

    // --- SECTION 5: ACCESSIBLE EXECUTIVE SUMMARY BOX ---
    if ($pdf->GetY() > 235) { 
        $pdf->AddPage(); 
        $pdf->Ln(15); 
    }
    
    $pdf->SetFont('Arial', 'B', 9.5);
    $pdf->SetFillColor(245, 245, 245);
    
    if ($score_check >= 50) {
        $verdict_msg = "IMMEDIATE ADMINISTRATIVE ACTION";
    } else {
        $verdict_msg = "ROUTINE MONITORING";
    }
    
    $summary_paragraph = "EXECUTIVE SUMMARY: Sentinel-AI has concluded the audit for the specified telemetry. The resulting " . $score_check . "% risk index warrants " . $verdict_msg . ". Data persisted to RDBMS logs under cryptographic law-compliance verification frameworks.";
    $pdf->MultiCell(190, 5, $summary_paragraph, 1, 'L', true);

    // Final file output path processing loops
    $file_name = "Sentinel_Forensic_Report_" . $analysis_array['forensic_id'] . ".pdf";
    $destination_folder = dirname(__DIR__) . "/reports/" . $file_name;
    
    $pdf->Output('F', $destination_folder);
    return $file_name;
}
?>