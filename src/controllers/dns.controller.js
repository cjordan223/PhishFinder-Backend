// src/controllers/dns.controller.js

//this controller handles the fetching of the email security info from the DNS records

import { getEmailAuthenticationDetails } from '../services/dns.service.js';

export const getDNSRecords = async (req, res) => {
  const { domain } = req.params;
  console.log(`Fetching DNS records for domain: ${domain}`);
  try {
    const dnsRecords = await getEmailAuthenticationDetails(domain);
    console.log('DNS Records:', dnsRecords);
    res.json(dnsRecords);
  } catch (error) {
    console.error('Error fetching DNS records:', error);
    res.status(500).json({ error: 'Error fetching DNS records' });
  }
};