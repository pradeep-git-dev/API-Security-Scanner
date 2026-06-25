import { Response } from 'express';
import Scan from '../models/Scan';
import Vulnerability from '../models/Vulnerability';
import Report from '../models/Report';
import ScanLog from '../models/ScanLog';
import { createScanSchema } from '../validators/scanValidator';
import { AuthenticatedRequest } from '../types';
import { scanTarget } from '../services/scannerService';
import { enrichVulnerability } from '../services/aiService';

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

    const { targetUrl } = validation.data;

    // 2. Create scan document in DB
    const scan = await Scan.create({
      userId: req.user.id,
      targetUrl,
      sourceType: 'web',
      status: 'PENDING',
      progress: 0,
      score: 0,
      totalEndpointsScanned: 0,
      scannerVersion: '1.0.0',
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

    // Retrieve only user's scans, sorted by createdAt descending
    const scans = await Scan.find({ userId: req.user.id }).sort({ createdAt: -1 });

    // Calculate statistics
    const totalScans = scans.length;
    
    // Average score across completed scans, default to 100 if no scans
    const completedScans = scans.filter(s => s.status === 'COMPLETED');
    const averageScore = completedScans.length === 0
      ? 100
      : Math.round(completedScans.reduce((acc, s) => acc + (s.score || 0), 0) / completedScans.length);

    // Get count of critical vulnerabilities across all of user's scans
    const scanIds = scans.map(s => s._id);
    const criticalFindings = await Vulnerability.countDocuments({
      scanId: { $in: scanIds },
      severity: 'CRITICAL',
    });

    return res.json({
      scans,
      stats: {
        totalScans,
        averageScore,
        criticalFindings,
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

    // Verify ownership
    if (scan.userId.toString() !== req.user.id) {
      return res.status(403).json({ message: 'Access denied: You do not own this scan' });
    }

    // Fetch associated findings with their AI enrichment data
    const findings = await Vulnerability.find({ scanId: scan._id });

    return res.json({ scan, findings });
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

    // Verify ownership
    if (scan.userId.toString() !== req.user.id) {
      return res.status(403).json({ message: 'Access denied: You do not own this scan' });
    }

    // Delete scan and all associated data
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

    // Verify ownership
    if (scan.userId.toString() !== req.user.id) {
      return res.status(403).json({ message: 'Access denied: You do not own this scan' });
    }

    // 1. Update status to SCANNING and save
    scan.status = 'SCANNING' as any;
    scan.startedAt = new Date();
    await scan.save();

    const startTime = Date.now();

    // 2. Call FastAPI service and handle errors
    let findings;
    try {
      findings = await scanTarget(scan.targetUrl);
    } catch (scanErr: any) {
      scan.status = 'FAILED' as any;
      await scan.save();
      throw scanErr;
    }

    // Clear any existing vulnerabilities and reports for this scan to prevent duplicate findings on re-run
    await Vulnerability.deleteMany({ scanId: scan._id });
    await Report.deleteMany({ scanId: scan._id });

    // 3. Save Vulnerability documents in MongoDB
    const vulnerabilityDocs = findings.map((f: any) => ({
      scanId: scan._id,
      endpoint: f.endpoint,
      method: f.method,
      issue: f.issue,
      severity: f.severity,
      confidence: f.confidence,
      description: f.description,
      recommendation: f.recommendation,
      detectedAt: new Date(),
    }));

    let savedDocs: any[] = [];
    if (vulnerabilityDocs.length > 0) {
      savedDocs = await Vulnerability.insertMany(vulnerabilityDocs);

      // Call Gemini for each vulnerability finding and enrich with explanation, impact, fix, and code example
      for (const doc of savedDocs) {
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

    // 4. Calculate severity counts and score (100 - penalties)
    let critical = 0;
    let high = 0;
    let medium = 0;
    let low = 0;

    findings.forEach((f: any) => {
      const sev = f.severity.toUpperCase();
      if (sev === 'CRITICAL') critical++;
      else if (sev === 'HIGH') high++;
      else if (sev === 'MEDIUM') medium++;
      else if (sev === 'LOW') low++;
    });

    const penalty = (critical * 25) + (high * 15) + (medium * 10) + (low * 5);
    const score = Math.max(0, 100 - penalty);

    // 5. Create and save Report document
    const report = await Report.create({
      scanId: scan._id,
      critical,
      high,
      medium,
      low,
      score,
      generatedAt: new Date(),
    });

    // 6. Update Scan status, completedAt, durationMs, and score
    const durationMs = Date.now() - startTime;
    scan.status = 'COMPLETED' as any;
    scan.completedAt = new Date();
    scan.durationMs = durationMs;
    scan.score = score;
    
    // Calculate totalEndpointsScanned based on unique endpoints from findings, fallback to 1
    const uniqueEndpoints = new Set(findings.map((f: any) => f.endpoint));
    scan.totalEndpointsScanned = Math.max(1, uniqueEndpoints.size);

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

