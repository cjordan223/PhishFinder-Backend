// src/controllers/dns.controller.js

// This controller handles the fetching of the email security info from the DNS records
import { getEmailAuthenticationDetails } from '../services/dns.service.js';
import logger from '../config/logger.js';

export const getDNSRecords = async (req, res) => {
  const { domain } = req.params;
  logger.info(`Fetching DNS records for domain: ${domain}`);
  try {
    const dnsRecords = await getEmailAuthenticationDetails(domain);
    logger.info('DNS Records:', dnsRecords);
    res.json(dnsRecords);
  } catch (error) {
    logger.error('Error fetching DNS records:', error);
    res.status(500).json({ error: 'Error fetching DNS records' });
  }
};