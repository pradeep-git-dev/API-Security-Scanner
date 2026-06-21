import { Router } from 'express';
import {
  createScan,
  getUserScans,
  getScanById,
  deleteScan,
} from '../controllers/scanController';
import { protect } from '../middleware/authMiddleware';

const router = Router();

// Protect all routes below this middleware
router.use(protect as any);

router.post('/scan', createScan as any);
router.get('/scans', getUserScans as any);
router.get('/scan/:id', getScanById as any);
router.delete('/scan/:id', deleteScan as any);

export default router;
