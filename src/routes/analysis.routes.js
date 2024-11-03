// src/routes/analysis.routes.js
import express from 'express';
import { saveAnalysis, analyzeContent, analyzeAIContent, analyzeEmail } from '../controllers/analysis.controller.js';

const router = express.Router();
router.post('/saveEmailAnalysis', saveAnalysis);
router.post('/analyze', analyzeContent);
router.post('/ai-analyze', analyzeAIContent);
router.post('/analyze-email', analyzeEmail); // Add this new route


export default router;
