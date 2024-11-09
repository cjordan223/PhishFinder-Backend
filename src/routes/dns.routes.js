// src/routes/dns.routes.js

// defines the routes for the DNS records
import express from 'express';
import rateLimit from 'express-rate-limit';
import { getDNSRecords } from '../controllers/dns.controller.js';

const router = express.Router();

// Rate limiting: 100 requests per 15 minutes per IP
const dnsLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many DNS requests, please try again later (This is a CJ Error not an API Error - check DNS Routes)' }
});

// Validate domain parameter middleware
const validateDomain = (req, res, next) => {
  const domain = req.params.domain;
  if (!domain || domain.length > 253 || !/^[a-zA-Z0-9][a-zA-Z0-9-_.]+[a-zA-Z0-9]$/.test(domain)) {
    return res.status(400).json({ error: 'Invalid domain format' });
  }
  next();
};

router.get('/dns-records/:domain', dnsLimiter, validateDomain, getDNSRecords);

export default router;