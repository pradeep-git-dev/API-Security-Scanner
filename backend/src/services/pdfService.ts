import PDFDocument from 'pdfkit';

/**
 * Generates a professional, commercial-grade PDF security report for a scan.
 */
export const generateScanPDF = (scan: any, report: any, findings: any[]): Promise<Buffer> => {
  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({ margin: 50, bufferPages: true });
      const buffers: Buffer[] = [];

      doc.on('data', (chunk) => buffers.push(chunk));
      doc.on('end', () => resolve(Buffer.concat(buffers)));
      doc.on('error', (err) => reject(err));

      const score = report?.score ?? 0;
      const targetType = report?.targetType ?? 'UNKNOWN';
      const framework = report?.framework ?? 'Unknown';
      const server = report?.server ?? 'Unknown';
      const contentType = report?.contentType ?? 'Unknown';
      const tlsVersion = report?.tlsVersion ?? 'N/A';
      const responseTimeMs = report?.responseTimeMs ?? 0;

      // Group findings by category
      const secFindings = findings.filter(f => f.category === 'Security Findings');
      const observations = findings.filter(f => f.category === 'Observations');
      const passedChecks = findings.filter(f => f.category === 'Passed Checks');
      const infoFindings = findings.filter(f => f.category === 'Informational');

      // --- PAGE 1: COVER & EXECUTIVE SUMMARY ---

      // Header Banner
      doc.fillColor('#1e1b4b').rect(0, 0, doc.page.width, 125).fill();
      doc.fillColor('#ffffff').fontSize(24).font('Helvetica-Bold').text('API SENTINEL', 50, 35);
      doc.fontSize(11).font('Helvetica').text('Security Assessment & Vulnerability Report', 50, 65);
      
      const targetInfoText = `${targetType} (${framework})`;
      doc.fontSize(10).font('Helvetica-Bold').fillColor('#818cf8').text(`Target Profile: ${targetInfoText}`, 50, 85);

      // Reset text color
      doc.fillColor('#0f172a');

      // Score & Severity Summary section
      doc.fontSize(15).font('Helvetica-Bold').text('Security Score & Posture', 50, 145);
      
      // 1. Draw Score Box
      let scoreColor = '#16a34a'; // Green
      if (score < 70) scoreColor = '#dc2626'; // Red
      else if (score < 90) scoreColor = '#d97706'; // Amber

      doc.fillColor('#f8fafc').rect(50, 165, 110, 95).fill();
      doc.strokeColor('#cbd5e1').rect(50, 165, 110, 95).stroke();
      doc.fillColor('#475569').fontSize(8.5).font('Helvetica-Bold').text('Security Score', 50, 173, { align: 'center', width: 110 });
      doc.fillColor(scoreColor).fontSize(30).font('Helvetica-Bold').text(`${score}`, 50, 190, { align: 'center', width: 110 });
      doc.fillColor('#64748b').fontSize(8.5).font('Helvetica').text('out of 100', 50, 235, { align: 'center', width: 110 });

      // 2. Draw Confidence Box
      const confidence = report?.confidence || { score: 100, label: 'HIGH' };
      let confColor = '#16a34a'; // Green for HIGH
      if (confidence.label === 'LOW') confColor = '#dc2626';
      else if (confidence.label === 'MEDIUM') confColor = '#d97706';

      doc.fillColor('#f8fafc').rect(170, 165, 110, 95).fill();
      doc.strokeColor('#cbd5e1').rect(170, 165, 110, 95).stroke();
      doc.fillColor('#475569').fontSize(8.5).font('Helvetica-Bold').text('Confidence', 170, 173, { align: 'center', width: 110 });
      doc.fillColor(confColor).fontSize(30).font('Helvetica-Bold').text(`${confidence.score}%`, 170, 190, { align: 'center', width: 110 });
      doc.fillColor(confColor).fontSize(8.5).font('Helvetica-Bold').text(confidence.label, 170, 235, { align: 'center', width: 110 });

      // 3. Draw Category Breakdown Box
      doc.fillColor('#f8fafc').rect(290, 165, 272, 95).fill();
      doc.strokeColor('#cbd5e1').rect(290, 165, 272, 95).stroke();
      doc.fillColor('#475569').fontSize(8.5).font('Helvetica-Bold').text('Category Breakdown', 300, 173);

      const categories = report?.categories || [
        { name: 'Header Security', score: 30, max: 30, percentage: 100 },
        { name: 'Transport Security', score: 15, max: 15, percentage: 100 },
        { name: 'Server Security', score: 15, max: 15, percentage: 100 },
        { name: 'API Security', score: 25, max: 25, percentage: 100 },
        { name: 'Data Protection', score: 15, max: 15, percentage: 100 }
      ];

      let rowY = 190;
      categories.forEach((cat: any) => {
        doc.fillColor('#334155').fontSize(7).font('Helvetica-Bold').text(cat.name, 300, rowY, { width: 95 });
        
        // Progress Bar
        const barX = 400;
        const barWidth = 110;
        const barHeight = 4;
        
        doc.fillColor('#e2e8f0').rect(barX, rowY + 2, barWidth, barHeight).fill();
        const activeWidth = barWidth * (cat.percentage / 100);
        if (activeWidth > 0) {
          doc.fillColor('#4f46e5').rect(barX, rowY + 2, activeWidth, barHeight).fill();
        }
        
        // Score
        doc.fillColor('#475569').fontSize(7).font('Helvetica-Bold').text(`${cat.score}/${cat.max}`, 515, rowY, { align: 'right', width: 40 });
        rowY += 13;
      });

      // Metadata & Findings count summaries
      doc.fillColor('#0f172a').fontSize(14).font('Helvetica-Bold').text('Scan Intelligence Summary', 50, 278);
      
      // Draw grid boxes for counts
      const boxW = 118;
      const boxH = 50;
      const boxGap = 13;
      const boxY = 300;

      // Security Findings
      doc.fillColor('#fef2f2').rect(50, boxY, boxW, boxH).fill();
      doc.strokeColor('#fca5a5').rect(50, boxY, boxW, boxH).stroke();
      doc.fillColor('#b91c1c').fontSize(9).font('Helvetica-Bold').text('SECURITY FINDINGS', 60, boxY + 12);
      doc.fontSize(16).text(`${secFindings.length}`, 60, boxY + 26);

      // Observations
      const obsX = 50 + boxW + boxGap;
      doc.fillColor('#fffbeb').rect(obsX, boxY, boxW, boxH).fill();
      doc.strokeColor('#fde68a').rect(obsX, boxY, boxW, boxH).stroke();
      doc.fillColor('#d97706').fontSize(9).font('Helvetica-Bold').text('OBSERVATIONS', obsX + 10, boxY + 12);
      doc.fontSize(16).text(`${observations.length}`, obsX + 10, boxY + 26);

      // Passed Checks
      const passX = obsX + boxW + boxGap;
      doc.fillColor('#f0fdf4').rect(passX, boxY, boxW, boxH).fill();
      doc.strokeColor('#bbf7d0').rect(passX, boxY, boxW, boxH).stroke();
      doc.fillColor('#15803d').fontSize(9).font('Helvetica-Bold').text('PASSED CHECKS', passX + 10, boxY + 12);
      doc.fontSize(16).text(`${passedChecks.length}`, passX + 10, boxY + 26);

      // Informational
      const infoX = passX + boxW + boxGap;
      doc.fillColor('#f0f9ff').rect(infoX, boxY, boxW, boxH).fill();
      doc.strokeColor('#bae6fd').rect(infoX, boxY, boxW, boxH).stroke();
      doc.fillColor('#0369a1').fontSize(9).font('Helvetica-Bold').text('INFORMATIONAL', infoX + 10, boxY + 12);
      doc.fontSize(16).text(`${infoFindings.length}`, infoX + 10, boxY + 26);

      // Metadata details & Header analysis table
      let detailsY = 368;
      doc.fillColor('#0f172a').fontSize(14).font('Helvetica-Bold').text('Environment Metadata', 50, detailsY);
      doc.fontSize(14).text('Header Verification', 310, detailsY);

      // Draw Metadata list
      detailsY += 18;
      doc.fontSize(9.5).strokeColor('#e2e8f0').lineWidth(0.5);
      
      const drawMetadataRow = (label: string, val: string, y: number) => {
        doc.fillColor('#64748b').font('Helvetica-Bold').text(label, 50, y);
        doc.fillColor('#334155').font('Helvetica').text(val, 160, y, { width: 130 });
        doc.moveTo(50, y + 12).lineTo(290, y + 12).stroke();
      };

      drawMetadataRow('Target Profile', targetType, detailsY);
      drawMetadataRow('Framework', framework, detailsY + 15);
      drawMetadataRow('Server', server, detailsY + 30);
      drawMetadataRow('Content-Type', contentType, detailsY + 45);
      drawMetadataRow('TLS Version', tlsVersion, detailsY + 60);
      drawMetadataRow('Response Time', `${responseTimeMs} ms`, detailsY + 75);

      // Draw Header status table
      let headersY = 368 + 18;
      const headersList = report?.headersStatus || [];
      if (headersList.length === 0) {
        doc.fillColor('#64748b').font('Helvetica').fontSize(9).text('No header statuses checked.', 310, headersY);
      } else {
        headersList.forEach((h: any) => {
          doc.fillColor('#334155').font('Helvetica-Bold').fontSize(8.5).text(h.header, 310, headersY);
          const statusChar = h.status ? 'PASS' : 'FAIL';
          const statusCol = h.status ? '#16a34a' : '#dc2626';
          doc.fillColor(statusCol).font('Helvetica-Bold').text(statusChar, 510, headersY, { align: 'right', width: 50 });
          doc.moveTo(310, headersY + 12).lineTo(562, headersY + 12).stroke();
          headersY += 15;
        });
      }

      // Rate limit test report summary
      let rateLimitY = 482;
      doc.fillColor('#0f172a').fontSize(14).font('Helvetica-Bold').text('Rate Limit Test Summary', 50, rateLimitY);
      
      doc.fillColor('#f8fafc').rect(50, rateLimitY + 18, 512, 55).fill();
      doc.strokeColor('#cbd5e1').rect(50, rateLimitY + 18, 512, 55).stroke();

      const rlData = report?.rateLimitReport || { requestsSent: 30, responses429: 0, retryAfter: 'Missing', conclusion: 'Unable to verify rate limiting.' };
      doc.fontSize(8.5).fillColor('#475569').font('Helvetica-Bold');
      doc.text('Requests Sent:', 65, rateLimitY + 28);
      doc.text('429 Responses:', 195, rateLimitY + 28);
      doc.text('Retry-After:', 325, rateLimitY + 28);
      
      doc.font('Helvetica').fillColor('#334155');
      doc.text(`${rlData.requestsSent}`, 140, rateLimitY + 28);
      doc.text(`${rlData.responses429}`, 270, rateLimitY + 28);
      doc.text(`${rlData.retryAfter}`, 380, rateLimitY + 28);

      doc.font('Helvetica-Bold').fillColor('#475569').text('Conclusion:', 65, rateLimitY + 48);
      doc.font('Helvetica').fillColor('#334155').text(rlData.conclusion, 130, rateLimitY + 48, { width: 420 });

      // Detailed Deductions section at the bottom of Page 1
      let deductionsY = 562;
      doc.fillColor('#0f172a').fontSize(14).font('Helvetica-Bold').text('Detailed Deductions', 50, deductionsY);
      
      doc.fillColor('#f8fafc').rect(50, deductionsY + 18, 512, 90).fill();
      doc.strokeColor('#cbd5e1').rect(50, deductionsY + 18, 512, 90).stroke();
      
      let deductionListY = deductionsY + 26;
      doc.font('Helvetica').fontSize(8).fillColor('#475569');
      
      const deductions = report?.scoreBreakdown || [];
      if (deductions.length === 0) {
        doc.font('Helvetica-Oblique').text('No deductions applied. High security posture!', 65, deductionListY);
      } else {
        // Show up to 5 deductions to fit inside the box
        deductions.slice(0, 5).forEach((item: any) => {
          const categoryName = item.category || 'General';
          doc.fillColor('#64748b').text(`[${categoryName}]`, 65, deductionListY);
          doc.fillColor('#334155').text(item.reason, 195, deductionListY);
          doc.fillColor('#b91c1c').font('Helvetica-Bold').text(`-${item.penalty}`, 510, deductionListY, { align: 'right', width: 40 });
          doc.font('Helvetica');
          deductionListY += 12;
        });
        if (deductions.length > 5) {
          doc.fillColor('#64748b').font('Helvetica-Oblique').text('Other deductions listed in scan results...', 65, deductionListY);
        }
      }

      // Footer will be added in final pass

      // --- DETAILED FINDINGS PAGES (GROUPED BY CATEGORY) ---
      const categoriesOrder = ['Security Findings', 'Observations', 'Passed Checks', 'Informational'];

      categoriesOrder.forEach((category) => {
        const catFindings = findings.filter(f => f.category === category);
        if (catFindings.length === 0) return;

        doc.addPage();
        doc.fillColor('#1e1b4b').rect(0, 0, doc.page.width, 60).fill();
        doc.fillColor('#ffffff').fontSize(14).font('Helvetica-Bold').text(category, 50, 23);

        let currentY = 85;

        catFindings.forEach((finding, index) => {
          // If the finding doesn't fit on the current page, and we are not already at the top of a page
          const findingHeight = getFindingHeight(doc, finding);
          const pageBottomLimit = doc.page.height - 60;
          if (currentY > 85 && currentY + findingHeight > pageBottomLimit) {
            doc.addPage();
            doc.fillColor('#1e1b4b').rect(0, 0, doc.page.width, 40).fill();
            doc.fillColor('#ffffff').fontSize(11).font('Helvetica-Bold').text(`${category} (Continued)`, 50, 15);
            currentY = 60;
          }

          // Header for individual finding
          doc.fillColor('#0f172a').fontSize(11).font('Helvetica-Bold').text(`${index + 1}. ${finding.issue}`, 50, currentY);
          
          let sevColor = '#64748b'; // Grey for Passed/Info
          if (category === 'Security Findings') {
            const sev = finding.severity.toUpperCase();
            if (sev === 'CRITICAL') sevColor = '#7c3aed';
            else if (sev === 'HIGH') sevColor = '#dc2626';
            else if (sev === 'MEDIUM') sevColor = '#d97706';
            else if (sev === 'LOW') sevColor = '#2563eb';
          }
          
          doc.fillColor(sevColor).fontSize(8.5).font('Helvetica-Bold').text(finding.severity, 480, currentY, { align: 'right', width: 80 });
          currentY += 15;

          // Target endpoint details
          doc.fillColor('#475569').fontSize(8.5).font('Helvetica-Bold').text('ENDPOINT:', 50, currentY);
          doc.font('Helvetica').fillColor('#334155').text(`${finding.method.toUpperCase()} ${finding.endpoint}`, 110, currentY, { width: 320 });
          
          // Mappings for standard bodies
          if (finding.owasp || finding.cwe) {
            doc.font('Helvetica-Bold').fillColor('#475569').text('STANDARDS:', 400, currentY);
            let standardsText = '';
            if (finding.owasp) standardsText += finding.owasp;
            if (finding.cwe) standardsText += (standardsText ? ' | ' : '') + finding.cwe;
            doc.font('Helvetica').fillColor('#334155').text(standardsText, 465, currentY, { align: 'right', width: 97 });
          }
          currentY += 15;

          // Description
          doc.font('Helvetica-Bold').fillColor('#334155').text('Description:', 50, currentY);
          doc.font('Helvetica').fillColor('#475569').text(finding.description, 50, currentY + 12, { width: 512, align: 'justify' });
          currentY = doc.y + 8;

          // Format structured evidence
          const evidence = finding.evidence;
          if (evidence) {
            doc.font('Helvetica-Bold').fillColor('#334155').text('Evidence:', 50, currentY);
            doc.font('Helvetica').fillColor('#475569');
            let evidenceText = '';
            if (typeof evidence === 'object') {
              if (evidence.type === 'missing_headers' && Array.isArray(evidence.details)) {
                evidenceText = `Missing Headers: ${evidence.details.join(', ')}`;
              } else if (Array.isArray(evidence.details)) {
                evidenceText = evidence.details.map((line: string) => `• ${line}`).join('\n');
              } else if (evidence.details) {
                evidenceText = String(evidence.details);
              } else {
                evidenceText = JSON.stringify(evidence, null, 2);
              }
            } else {
              evidenceText = String(evidence);
            }
            doc.text(evidenceText, 50, currentY + 12, { width: 512 });
            currentY = doc.y + 8;
          }

          // Impact (if not empty)
          if (finding.impact && finding.impact !== 'None') {
            doc.font('Helvetica-Bold').fillColor('#991b1b').text('Impact:', 50, currentY);
            doc.font('Helvetica').fillColor('#475569').text(finding.impact, 50, currentY + 12, { width: 512 });
            currentY = doc.y + 8;
          }

          // Recommendation
          if (finding.recommendation && finding.recommendation !== 'Informational only.') {
            doc.font('Helvetica-Bold').fillColor('#166534').text('Recommendation:', 50, currentY);
            doc.font('Helvetica').fillColor('#475569').text(finding.recommendation, 50, currentY + 12, { width: 512 });
            currentY = doc.y + 12;
          }

          // Secure Code Example (AI fix) if present
          if (finding.codeExample) {
            doc.font('Helvetica-Bold').fillColor('#3730a3').text('Secure Implementation Example:', 50, currentY);
            currentY += 14;

            const codeText = finding.codeExample;
            // Calculate code text height dynamically
            doc.font('Courier').fontSize(8);
            const codeHeight = doc.heightOfString(codeText, { width: 490, lineGap: 2 });
            const boxHeight = codeHeight + 20;

            // Draw background card for code
            doc.fillColor('#1e293b').rect(50, currentY, 512, boxHeight).fill();
            doc.fillColor('#e2e8f0');
            doc.text(codeText, 60, currentY + 10, { width: 490, lineGap: 2 });
            
            currentY += boxHeight + 15;
          } else {
            currentY += 10;
          }

          // Separator line between findings
          doc.strokeColor('#e2e8f0').lineWidth(0.5).moveTo(50, currentY).lineTo(562, currentY).stroke();
          currentY += 15;
        });

      });

      // Switch to each page and add footer
      const range = doc.bufferedPageRange();
      for (let i = 0; i < range.count; i++) {
        doc.switchToPage(i);
        addPageFooter(doc, i + 1, range.count);
      }

      doc.end();
    } catch (err) {
      reject(err);
    }
  });
};

const addPageFooter = (doc: PDFKit.PDFDocument, pageNum: number, totalPages: number) => {
  doc.save();
  const oldBottomMargin = doc.page.margins.bottom;
  doc.page.margins.bottom = 0;

  doc.strokeColor('#cbd5e1').lineWidth(0.5).moveTo(50, doc.page.height - 50).lineTo(doc.page.width - 50, doc.page.height - 50).stroke();
  doc.fillColor('#64748b').font('Helvetica').fontSize(8);
  doc.text('API Sentinel Security Assessment — Confidential Report', 50, doc.page.height - 42);
  doc.text(`Page ${pageNum} of ${totalPages}`, doc.page.width - 120, doc.page.height - 42, { align: 'right', width: 70 });

  doc.page.margins.bottom = oldBottomMargin;
  doc.restore();
};

const getFindingHeight = (doc: PDFKit.PDFDocument, finding: any): number => {
  let height = 0;

  // Title / Issue name
  doc.font('Helvetica-Bold').fontSize(11);
  height += doc.heightOfString(finding.issue, { width: 420 }) + 10;

  // Endpoint line
  height += 15;

  // Description
  doc.font('Helvetica').fontSize(8.5);
  height += 15 + doc.heightOfString(finding.description, { width: 512 }) + 8;

  // Evidence
  if (finding.evidence) {
    let evidenceText = '';
    const evidence = finding.evidence;
    if (typeof evidence === 'object') {
      if (evidence.type === 'missing_headers' && Array.isArray(evidence.details)) {
        evidenceText = `Missing Headers: ${evidence.details.join(', ')}`;
      } else if (Array.isArray(evidence.details)) {
        evidenceText = evidence.details.map((line: string) => `• ${line}`).join('\n');
      } else if (evidence.details) {
        evidenceText = String(evidence.details);
      } else {
        evidenceText = JSON.stringify(evidence, null, 2);
      }
    } else {
      evidenceText = String(evidence);
    }

    doc.font('Helvetica').fontSize(8.5);
    height += 15 + doc.heightOfString(evidenceText, { width: 512 }) + 8;
  }

  // Impact
  if (finding.impact && finding.impact !== 'None') {
    doc.font('Helvetica').fontSize(8.5);
    height += 15 + doc.heightOfString(finding.impact, { width: 512 }) + 8;
  }

  // Recommendation
  if (finding.recommendation && finding.recommendation !== 'Informational only.') {
    doc.font('Helvetica').fontSize(8.5);
    height += 15 + doc.heightOfString(finding.recommendation, { width: 512 }) + 12;
  }

  // Code Example
  if (finding.codeExample) {
    doc.font('Courier').fontSize(8);
    const codeHeight = doc.heightOfString(finding.codeExample, { width: 490, lineGap: 2 });
    height += 15 + codeHeight + 20 + 15;
  }

  // Separator
  height += 15;

  return height;
};
