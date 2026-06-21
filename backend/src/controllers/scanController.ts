import { Response } from 'express';
import Scan from '../models/Scan';
import Vulnerability from '../models/Vulnerability';
import Report from '../models/Report';
import ScanLog from '../models/ScanLog';
import { createScanSchema } from '../validators/scanValidator';
import { AuthenticatedRequest } from '../types';

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

    return res.json({ scans });
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

    return res.json({ scan });
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
