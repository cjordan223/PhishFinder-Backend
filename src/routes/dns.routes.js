// src/routes/dns.routes.js

// defines the routes for the DNS records
import express from 'express';
import { getDNSRecords } from '../controllers/dns.controller.js';

const router = express.Router();
router.get('/dns-records/:domain', getDNSRecords);

export default router;