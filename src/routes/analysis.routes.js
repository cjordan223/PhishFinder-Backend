// src/routes/analysis.routes.js
import express from 'express';
import { saveAnalysis, analyzeContent, analyzeAIContent } from '../controllers/analysis.controller.js';

const router = express.Router();
router.post('/saveEmailAnalysis', saveAnalysis);
router.post('/analyze', analyzeContent);
router.post('/ai-analyze', analyzeAIContent);

export default router;
