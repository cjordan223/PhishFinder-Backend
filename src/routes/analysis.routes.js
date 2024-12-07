import express from 'express';
import { analyzeEmail, analyzeEmailOnly, getEmailAnalysis, getSenderProfile } from '../controllers/analysis.controller.js';
import { analyzeAIContent } from '../services/analysis.service.js'

const router = express.Router();
router.post('/saveEmailAnalysis', analyzeEmail);
router.post('/ai-analyze', analyzeAIContent);
router.post('/analyze-email', analyzeEmail);  // Use analyzeEmail for persistence
router.get('/email/:id', getEmailAnalysis);   // Use getEmailAnalysis for retrieval on FE
router.post('/analyze-only/:id', analyzeEmailOnly);  // Use analyzeEmailOnly for analysis without persistence
router.get('/sender/:email', getSenderProfile);

export default router;