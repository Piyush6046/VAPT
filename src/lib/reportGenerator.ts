import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";
import { AuditFinding, LiveAuditResult } from "./auditEngine";

export function generateProfessionalReport(
  target: string,
  findings: AuditFinding[],
  riskScore: number,
  liveResult?: LiveAuditResult
) {
  const doc = new jsPDF("p", "mm", "a4");
  const pageWidth = doc.internal.pageSize.width;
  
  // Custom font sizing
  const titleSize = 24;
  const h1Size = 18;
  const h2Size = 14;
  const textSize = 11;

  // Colors
  const primaryColor = [15, 23, 42]; // Slate 900
  const accentColor = [16, 185, 129]; // Emerald 500
  const dangerColor = [239, 68, 68]; // Red 500
  const textDark = [51, 65, 85];

  // Helper to draw header
  const drawHeader = (doc: jsPDF, pageTitle: string) => {
    doc.setFillColor(primaryColor[0], primaryColor[1], primaryColor[2]);
    doc.rect(0, 0, pageWidth, 25, "F");
    doc.setTextColor(255, 255, 255);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(h1Size);
    doc.text(`Sentinel Threat Engine™ - ${pageTitle}`, 14, 16);
  };

  // --- PAGE 1: EXECUTIVE SUMMARY ---
  drawHeader(doc, "Executive Summary");

  doc.setTextColor(primaryColor[0], primaryColor[1], primaryColor[2]);
  doc.setFontSize(titleSize);
  doc.text("Vulnerability Assessment Report", 14, 45);

  doc.setFontSize(textSize);
  doc.setTextColor(textDark[0], textDark[1], textDark[2]);
  doc.text(`Target Assessed: ${target}`, 14, 55);
  doc.text(`Date of Assessment: ${new Date().toLocaleDateString()}`, 14, 62);
  doc.text(`Assessment Profile: Full Penetration Test (Active/Passive)`, 14, 69);
  
  doc.setFont("helvetica", "bold");
  doc.setFontSize(h2Size);
  doc.text("Overall Risk Posture", 14, 85);
  
  doc.setFont("helvetica", "normal");
  doc.setFontSize(textSize);
  
  let riskRating = "Low";
  let riskColor = accentColor;
  if (riskScore > 7) { riskRating = "Critical"; riskColor = dangerColor; }
  else if (riskScore > 4) { riskRating = "Medium"; riskColor = [245, 158, 11]; }

  doc.setTextColor(riskColor[0], riskColor[1], riskColor[2]);
  doc.setFontSize(16);
  doc.text(`${riskScore}/10 - ${riskRating.toUpperCase()}`, 14, 95);
  
  doc.setTextColor(textDark[0], textDark[1], textDark[2]);
  doc.setFontSize(textSize);
  doc.text(
    `The security assessment discovered a total of ${findings.length} findings. ` +
    `Immediate attention should be directed to any Critical or High severity issues ` +
    `to prevent potential exploitation.`,
    14, 105, { maxWidth: pageWidth - 28 }
  );

  // Summary Table
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach(f => severityCounts[f.severity]++);

  autoTable(doc, {
    startY: 120,
    head: [["Severity", "Count", "Action Required"]],
    body: [
      ["Critical", severityCounts.critical.toString(), "Immediate Remediation Required"],
      ["High", severityCounts.high.toString(), "Fix within 7 days"],
      ["Medium", severityCounts.medium.toString(), "Fix within 30 days"],
      ["Low / Info", (severityCounts.low + severityCounts.info).toString(), "Review and harden"],
    ],
    theme: "grid",
    headStyles: { fillColor: primaryColor as [number, number, number] },
    alternateRowStyles: { fillColor: [241, 245, 249] }
  });

  // Recon Table
  doc.setFontSize(h2Size);
  doc.setTextColor(primaryColor[0], primaryColor[1], primaryColor[2]);
  doc.text("Network Reconnaissance", 14, (doc as any).lastAutoTable.finalY + 15);
  
  let reconBody = [
    ["Server / Technology", liveResult?.server || "Unknown"],
    ["Reachability", liveResult?.reachable ? "Online (HTTP 200/403)" : "Unreachable"]
  ];

  autoTable(doc, {
    startY: (doc as any).lastAutoTable.finalY + 20,
    head: [["Recon Property", "Discovered Value"]],
    body: reconBody,
    theme: "grid",
    headStyles: { fillColor: [71, 85, 105] as [number, number, number] },
    alternateRowStyles: { fillColor: [248, 250, 252] }
  });

  // --- PAGE 2: DETAILED FINDINGS ---
  doc.addPage();
  drawHeader(doc, "Detailed Technical Findings");

  let startY = 40;
  
  if (findings.length === 0) {
    doc.setTextColor(textDark[0], textDark[1], textDark[2]);
    doc.text("No significant vulnerabilities were identified during this assessment.", 14, startY);
  } else {
    findings.sort((a, b) => b.cvss - a.cvss).forEach((finding, index) => {
      if (startY > 250) {
        doc.addPage();
        drawHeader(doc, "Detailed Technical Findings (Cont.)");
        startY = 40;
      }

      doc.setFont("helvetica", "bold");
      doc.setFontSize(12);
      
      let sCol = accentColor;
      if(finding.severity === "critical" || finding.severity === "high") sCol = dangerColor;
      else if(finding.severity === "medium") sCol = [245, 158, 11];
      
      doc.setTextColor(sCol[0], sCol[1], sCol[2]);
      doc.text(`[${finding.severity.toUpperCase()}] ${finding.title}`, 14, startY);
      
      startY += 8;
      doc.setFont("helvetica", "normal");
      doc.setFontSize(10);
      doc.setTextColor(textDark[0], textDark[1], textDark[2]);
      
      doc.setFont("helvetica", "bold"); doc.text("CVSS Score:", 14, startY);
      doc.setFont("helvetica", "normal"); doc.text(finding.cvss.toString(), 45, startY);
      
      startY += 6;
      doc.setFont("helvetica", "bold"); doc.text("OWASP Cat:", 14, startY);
      doc.setFont("helvetica", "normal"); doc.text(finding.owaspCategory, 45, startY);

      startY += 6;
      doc.setFont("helvetica", "bold"); doc.text("Description:", 14, startY);
      doc.setFont("helvetica", "normal"); 
      const descLines = doc.splitTextToSize(finding.description, pageWidth - 45);
      doc.text(descLines, 45, startY);
      startY += (descLines.length * 5) + 1;

      doc.setFont("helvetica", "bold"); doc.text("Evidence:", 14, startY);
      doc.setFont("helvetica", "normal"); 
      const eviLines = doc.splitTextToSize(finding.evidence, pageWidth - 45);
      doc.text(eviLines, 45, startY);
      startY += (eviLines.length * 5) + 1;

      doc.setFont("helvetica", "bold"); doc.text("Remediation:", 14, startY);
      doc.setFont("helvetica", "normal"); 
      const remLines = doc.splitTextToSize(finding.remediation, pageWidth - 45);
      doc.text(remLines, 45, startY);
      
      startY += (remLines.length * 5) + 8;
      
      // Divider
      doc.setDrawColor(226, 232, 240);
      doc.line(14, startY, pageWidth - 14, startY);
      startY += 8;
    });
  }

  // --- SAVE DOC ---
  doc.save(`VAPT_Report_${target.replace(/[^a-z0-9]/gi, '_')}.pdf`);
}
