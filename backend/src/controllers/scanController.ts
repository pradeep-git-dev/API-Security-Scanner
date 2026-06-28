import { Response } from 'express';
import Scan from '../models/Scan';
import Vulnerability from '../models/Vulnerability';
import Report from '../models/Report';
import ScanLog from '../models/ScanLog';
import { createScanSchema } from '../validators/scanValidator';
import { AuthenticatedRequest } from '../types';
import { scanTarget, ScanResult } from '../services/scannerService';
import { enrichVulnerability } from '../services/aiService';
import { generateScanPDF } from '../services/pdfService';
import { calculateDrift } from '../services/comparisonService';

/**
 * @desc    Create a new scan
 * @route   POST /scan
 * @access  Private
 */
export const createScan = async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user) {
      return res.status(401).json({ message: 'Not authorized' });
    }

    // 1. Validate request body
    const validation = createScanSchema.safeParse(req.body);
    if (!validation.success) {
      return res.status(400).json({
        message: 'Validation failed',
        errors: validation.error.format(),
      });
    }

    const { targetUrl, authConfig, openApiSpec } = validation.data;

    // 2. Create scan document in DB (never store tokenValue)
    const scan = await Scan.create({
      userId: req.user.id,
      targetUrl,
      sourceType: openApiSpec ? 'openapi' : 'web',
      status: 'PENDING',
      progress: 0,
      score: 0,
      totalEndpointsScanned: 0,
      scannerVersion: '1.0.0',
      authConfig: authConfig ? {
        authType: authConfig.authType,
        headerName: authConfig.headerName,
      } : { authType: 'None' },
    });

    return res.status(201).json({
      message: 'Scan created successfully',
      scan,
    });
  } catch (error) {
    console.error('Create scan error:', error);
    return res.status(500).json({ message: 'Server error during scan creation' });
  }
};

/**
 * @desc    Get all scans for the logged-in user
 * @route   GET /scans
 * @access  Private
 */
export const getUserScans = async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user) {
      return res.status(401).json({ message: 'Not authorized' });
    }

    const scans = await Scan.find({ userId: req.user.id }).sort({ createdAt: -1 });

    const totalScans = scans.length;
    const completedScans = scans.filter(s => s.status === 'COMPLETED');
    const averageScore = completedScans.length === 0
      ? 100
      : Math.round(completedScans.reduce((acc, s) => acc + (s.score || 0), 0) / completedScans.length);

    const scanIds = scans.map(s => s._id);
    const criticalFindings = await Vulnerability.countDocuments({
      scanId: { $in: scanIds },
      severity: 'CRITICAL',
    });

    const lastScanTime = scans.length > 0 ? (scans[0].completedAt || scans[0].startedAt || scans[0].createdAt) : null;

    return res.json({
      scans,
      stats: {
        totalScans,
        averageScore,
        criticalFindings,
        lastScanTime,
      },
    });
  } catch (error) {
    console.error('Get scans error:', error);
    return res.status(500).json({ message: 'Server error fetching scans' });
  }
};

/**
 * @desc    Get details of a single scan
 * @route   GET /scan/:id
 * @access  Private
 */
export const getScanById = async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user) {
      return res.status(401).json({ message: 'Not authorized' });
    }

    const scan = await Scan.findById(req.params.id);
    if (!scan) {
      return res.status(404).json({ message: 'Scan not found' });
    }

    if (scan.userId.toString() !== req.user.id) {
      return res.status(403).json({ message: 'Access denied: You do not own this scan' });
    }

    const findings = await Vulnerability.find({ scanId: scan._id });
    const report = await Report.findOne({ scanId: scan._id });

    return res.json({ scan, report, findings });
  } catch (error) {
    console.error('Get scan by ID error:', error);
    return res.status(500).json({ message: 'Server error fetching scan details' });
  }
};

/**
 * @desc    Delete a scan and all associated data
 * @route   DELETE /scan/:id
 * @access  Private
 */
export const deleteScan = async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user) {
      return res.status(401).json({ message: 'Not authorized' });
    }

    const scan = await Scan.findById(req.params.id);
    if (!scan) {
      return res.status(404).json({ message: 'Scan not found' });
    }

    if (scan.userId.toString() !== req.user.id) {
      return res.status(403).json({ message: 'Access denied: You do not own this scan' });
    }

    await Scan.findByIdAndDelete(req.params.id);
    await Vulnerability.deleteMany({ scanId: scan._id });
    await Report.deleteMany({ scanId: scan._id });
    await ScanLog.deleteMany({ scanId: scan._id });

    return res.json({
      message: 'Scan and associated data deleted successfully',
      scanId: scan._id,
    });
  } catch (error) {
    console.error('Delete scan error:', error);
    return res.status(500).json({ message: 'Server error during scan deletion' });
  }
};

/**
 * @desc    Trigger scan execution (calls Python scanner)
 * @route   POST /scan/start/:id
 * @access  Private
 */
export const triggerScan = async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user) {
      return res.status(401).json({ message: 'Not authorized' });
    }

    const scan = await Scan.findById(req.params.id);
    if (!scan) {
      return res.status(404).json({ message: 'Scan not found' });
    }

    if (scan.userId.toString() !== req.user.id) {
      return res.status(403).json({ message: 'Access denied: You do not own this scan' });
    }

    // 1. Retrieve transient config properties from request body
    const { tokenValue, username, password, openApiSpec } = req.body;

    // Build the authConfig payload for python scanner execution
    const pythonAuthConfig = scan.authConfig ? {
      authType: scan.authConfig.authType,
      headerName: scan.authConfig.headerName,
      tokenValue: tokenValue || password,
      username: username,
      password: password,
    } : undefined;

    // 2. Update status to SCANNING
    scan.status = 'SCANNING' as any;
    scan.startedAt = new Date();
    await scan.save();

    const startTime = Date.now();

    // 3. Invoke FastAPI service passing transient OpenAPI spec and authConfig
    let scanResult: ScanResult;
    try {
      scanResult = await scanTarget(scan.targetUrl, openApiSpec, pythonAuthConfig);
    } catch (scanErr: any) {
      scan.status = 'FAILED' as any;
      await scan.save();
      throw scanErr;
    }

    // Clear any existing vulnerabilities/reports
    await Vulnerability.deleteMany({ scanId: scan._id });
    await Report.deleteMany({ scanId: scan._id });

    // 4. Save Vulnerability documents in MongoDB (adding findingId)
    const vulnerabilityDocs = scanResult.findings.map((f: any) => ({
      scanId: scan._id,
      findingId: f.findingId || '',
      endpoint: f.endpoint,
      method: f.method,
      issue: f.issue,
      severity: f.severity,
      confidence: f.confidence,
      description: f.description,
      recommendation: f.recommendation,
      category: f.category || 'Security Findings',
      evidence: f.evidence || null,
      impact: f.impact || '',
      owasp: f.owasp || '',
      cwe: f.cwe || '',
      detectedAt: new Date(),
    }));

    let savedDocs: any[] = [];
    if (vulnerabilityDocs.length > 0) {
      savedDocs = await Vulnerability.insertMany(vulnerabilityDocs);

      // Call Gemini AI for actual security findings enrichment
      for (const doc of savedDocs) {
        if (doc.category === 'Passed Checks' || doc.category === 'Informational' || doc.severity === 'INFO') {
          continue;
        }
        try {
          const aiResult = await enrichVulnerability(
            doc.issue,
            doc.severity,
            doc.description,
            doc.recommendation
          );

          doc.aiExplanation = aiResult.aiExplanation;
          doc.aiImpact = aiResult.aiImpact;
          doc.aiFix = aiResult.aiFix;
          doc.codeExample = aiResult.codeExample;

          await doc.save();
        } catch (enrichErr: any) {
          console.error(`[Scan Controller] Failed to enrich vulnerability ${doc._id}:`, enrichErr.message || enrichErr);
        }
      }
    }

    // 5. Query for previous completed scan reports to perform historical comparisons
    const previousScan = await Scan.findOne({
      userId: req.user.id,
      targetUrl: scan.targetUrl,
      status: 'COMPLETED',
      _id: { $ne: scan._id }
    }).sort({ completedAt: -1 });

    let drift = null;
    if (previousScan) {
      const previousFindings = await Vulnerability.find({ scanId: previousScan._id });
      const previousReport = await Report.findOne({ scanId: previousScan._id });
      if (previousReport) {
        drift = calculateDrift(
          previousReport.score,
          scanResult.score,
          previousFindings as any[],
          savedDocs as any[]
        );
      }
    }

    // 6. Calculate severity counts for statistics
    let critical = 0;
    let high = 0;
    let medium = 0;
    let low = 0;

    scanResult.findings.forEach((f: any) => {
      if (f.category === 'Passed Checks' || f.category === 'Informational') return;
      const sev = f.severity.toUpperCase();
      if (sev === 'CRITICAL') critical++;
      else if (sev === 'HIGH') high++;
      else if (sev === 'MEDIUM') medium++;
      else if (sev === 'LOW') low++;
    });

    // 7. Save Report document
    const report = await Report.create({
      scanId: scan._id,
      critical,
      high,
      medium,
      low,
      score: scanResult.score,
      generatedAt: new Date(),
      targetType: scanResult.targetType,
      framework: scanResult.framework,
      contentType: scanResult.contentType,
      server: scanResult.server,
      tlsVersion: scanResult.tlsVersion,
      responseTimeMs: scanResult.responseTimeMs,
      scoreBreakdown: scanResult.scoreBreakdown,
      categories: scanResult.categories,
      confidence: scanResult.confidence,
      headersStatus: scanResult.headersStatus,
      rateLimitReport: scanResult.rateLimitReport,
      endpointTree: scanResult.endpointTree || [],
      driftComparison: drift ? {
        previousScore: drift.previousScore,
        currentScore: drift.currentScore,
        difference: drift.difference,
        resolvedCount: drift.resolvedCount,
        newCount: drift.newCount,
        severityChanges: drift.severityChanges,
      } : {
        previousScore: 100,
        currentScore: scanResult.score,
        difference: 0,
        resolvedCount: 0,
        newCount: 0,
        severityChanges: [],
      }
    });

    // 8. Update Scan metadata properties (fingerprint & discoveryMetadata)
    const durationMs = Date.now() - startTime;
    scan.status = 'COMPLETED' as any;
    scan.completedAt = new Date();
    scan.durationMs = durationMs;
    scan.score = scanResult.score;
    scan.totalEndpointsScanned = scanResult.discoveryMetadata?.endpointCount || 1;
    
    scan.fingerprint = scanResult.fingerprint;
    scan.discoveryMetadata = scanResult.discoveryMetadata;

    await scan.save();

    return res.json({
      message: 'Scan completed successfully',
      scan,
      report,
      findings: savedDocs,
    });
  } catch (error: any) {
    console.error('Trigger scan error:', error);
    return res.status(500).json({ message: error.message || 'Server error during scan execution' });
  }
};

/**
 * @desc    Export scan report as PDF
 * @route   GET /scan/:id/pdf
 * @access  Private
 */
export const exportScanPDF = async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user) {
      return res.status(401).json({ message: 'Not authorized' });
    }

    const scan = await Scan.findById(req.params.id);
    if (!scan) {
      return res.status(404).json({ message: 'Scan not found' });
    }

    if (scan.userId.toString() !== req.user.id) {
      return res.status(403).json({ message: 'Access denied: You do not own this scan' });
    }

    const findings = await Vulnerability.find({ scanId: scan._id });
    const report = await Report.findOne({ scanId: scan._id });

    const pdfBuffer = await generateScanPDF(scan as any, report as any, findings as any[]);

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="API-Sentinel-Report-${scan._id}.pdf"`);
    return res.send(pdfBuffer);
  } catch (error: any) {
    console.error('Export PDF error:', error);
    return res.status(500).json({ message: 'Server error exporting PDF report' });
  }
};
