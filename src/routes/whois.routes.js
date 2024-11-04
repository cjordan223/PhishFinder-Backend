// src/routes/whois.routes.js
import express from 'express';
import { getWhoisData } from '../controllers/whois.controller.js';

const router = express.Router();

// Add logging middleware
router.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] Incoming ${req.method} request to ${req.originalUrl}`);
  next();
});

// Support both GET and POST methods
router.get('/:domain', getWhoisData);
router.get('/:domain/:emailId', getWhoisData);
router.post('/:domain', getWhoisData);
router.post('/:domain/:emailId', getWhoisData);

export default router;