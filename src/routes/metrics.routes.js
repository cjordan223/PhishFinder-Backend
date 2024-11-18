import express from 'express';
import { getMetrics } from '../controllers/metrics.controller.js';

const router = express.Router();

router.get('/:timeRange', getMetrics);

export default router;