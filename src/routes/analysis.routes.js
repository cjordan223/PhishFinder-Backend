// routes/analysis.routes.js
import express from 'express';
import { analyzeEmail } from '../controllers/analysis.controller.js';
import { analyzeAIContent } from '../services/analysis.service.js'

const router = express.Router();
router.post('/saveEmailAnalysis', analyzeEmail);
router.post('/ai-analyze', analyzeAIContent);
router.post('/analyze-email', analyzeEmail);

//removed /analyze route, need to adjust in front end

export default router;