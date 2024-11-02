import express from 'express';
import { getWhoisData } from '../controllers/whois.controller.js';

const router = express.Router();

router.get('/:domain', getWhoisData);

export default router;