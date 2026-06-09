<?php
// Project: Sentinel-AI Forensic Terminal
// File: cyber_law_helper.php
// Purpose: Helper function to draw colored law mapping tables with dynamic heights in PDF

function InjectStatutoryLawBoxes($pdf, $step, $metric_text, $weight_score) {
    // Check if vertical position crosses page safety limits to prevent crash
    if ($pdf->GetY() > 220) {
        $pdf->AddPage();
        $pdf->Ln(15); // Clear top margin on new sheet
    } else {
        $pdf->Ln(4); // Normal spacing between boxes
    }

    $pdf->SetFont('Arial', 'B', 10);
    $pdf->SetTextColor(33, 37, 41);
    
    $box_title = "";
    $it_act_section = "";
    $law_definition = "";
    $audit_message = "";
    
    // Set variables according to steps sequentially
    if ($step == 1) {
        $box_title = "STEP 1: PERIMETER INGESTION & VOLUMETRIC TRAFFIC MONITORING";
        $it_act_section = "Section 43(f) of the Information Technology (IT) Act, 2000";
        $law_definition = "Statutory Provision: Prevention of Denial of Service (DoS) and Unauthorized System Resource Depletion.";
        $audit_message = "Forensic Verification Audit: The boundary subsystem calculated the incoming transaction frequency profile of the packet stream. Rate limiting thresholds successfully prevented infrastructure thread starvation.";
        $bg_r = 235; $bg_g = 245; $bg_b = 255; // Blue Color Pack
        $brd_r = 0; $brd_g = 102; $brd_b = 204;
    } 
    else if ($step == 2) {
        $box_title = "STEP 2: HEURISTIC PATTERN SCRAMBLING & DEEP SYNTAX ANALYSIS";
        $it_act_section = "Section 66 Read With Section 43(i) of the IT Act, 2000";
        $law_definition = "Statutory Provision: Computer Related Offences - Tampering, Destroying, or Altering Destructive Source Code Assets.";
        $audit_message = "Forensic Verification Audit: Heuristic inspection matrix executed tokenized pattern evaluation loops. Parallel processing nodes scanned configuration streams for unauthorized system administration calls.";
        $bg_r = 255; $bg_g = 247; $bg_b = 235; // Amber Color Pack
        $brd_r = 204; $brd_g = 102; $brd_b = 0;
    } 
    else if ($step == 3) {
        $box_title = "STEP 3: NETWORK TRAJECTORY TRACING & REDIRECT LOOP ISOLATION";
        $it_act_section = "Section 43(f) & Section 66F of the Information Technology Act, 2000";
        $law_definition = "Statutory Provision: Protection Against Cyber Terrorism and Attempted Infrastructure Lockout via Resource Loops.";
        $audit_message = "Forensic Verification Audit: Active look-ahead sniffer framework intercepted remote host response headers. Redirection ceiling constraints successfully killed recursive redirect targets (Hmax Limit: 3).";
        $bg_r = 255; $bg_g = 240; $bg_b = 240; // Red Color Pack
        $brd_r = 204; $brd_g = 0; $brd_b = 0;
    } 
    else if ($step == 4) {
        $box_title = "STEP 4: CRYPTOGRAPHIC EVIDENCE SEALING & IMMUTABILITY RECONCILIATION";
        $it_act_section = "Section 65B of Indian Evidence Act & Section 66C of IT Act, 2000";
        $law_definition = "Statutory Provision: Admissibility of Electronic Records and Protection of Identity Integrity Verification Metrics.";
        $audit_message = "Forensic Verification Audit: System combined raw telemetry inputs, server session keys, and risk indicators into an immutable string hash block. Localized SHA-256 calculation sealed the digital evidence structure.";
        $bg_r = 240; $bg_g = 252; $bg_b = 240; // Green Color Pack
        $brd_r = 0; $brd_g = 153; $brd_b = 51;
    } else {
        return;
    }

    // Print out the step titles cleanly
    $pdf->Cell(190, 6, $box_title, 0, 1, 'L');

    // Display Technical logs trace line items
    $pdf->SetFont('Arial', '', 9.5);
    $pdf->SetTextColor(100, 100, 100);
    $pdf->Cell(43, 5, "Technical Context Captured: ", 0, 0, 'L');
    $pdf->SetFont('Arial', 'B', 9.5);
    $pdf->SetTextColor(33, 37, 41);
    $pdf->Cell(0, 5, $metric_text . " [Weight: " . $weight_score . "%]", 0, 1, 'L');
    $pdf->Ln(2);

    // Track original coordinate pointers for drawing perimeter shapes
    $x_start = $pdf->GetX();
    $y_start = $pdf->GetY();

    // Setup active drawing brush metrics
    $pdf->SetFillColor($bg_r, $bg_g, $bg_b);
    $pdf->SetDrawColor($brd_r, $brd_g, $brd_b);
    $pdf->SetLineWidth(0.3);

    // Inner heading section banner setup
    $pdf->SetFont('Arial', 'B', 9.5);
    $pdf->SetTextColor($brd_r, $brd_g, $brd_b);
    $pdf->Cell(190, 6, "  LAW COMPLIANCE BOUNDARY: " . $it_act_section, 0, 1, 'L', true);
    
    // Dynamic text rows execution
    $pdf->SetFont('Arial', 'I', 9);
    $pdf->SetTextColor(50, 50, 50);
    $pdf->MultiCell(190, 5, "  " . $law_definition, 0, 'L', true);
    
    $pdf->SetFont('Arial', '', 9);
    $pdf->SetTextColor(40, 40, 40);
    $pdf->MultiCell(190, 5, "  " . $audit_message, 0, 'L', true);

    // Space padding cell structure inside container logic
    $pdf->Cell(190, 2, "", 0, 1, 'L', true);

    // Calculate absolute box boundaries and lengths
    $y_end = $pdf->GetY();
    $box_total_height = $y_end - $y_start;
    
    // Create outermost enclosing neat table layout lines
    $pdf->Rect($x_start, $y_start, 190, $box_total_height, 'D');
    
    $pdf->Ln(3); 
}
?>