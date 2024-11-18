// src/controllers/whois.controller.js
import fetch from 'node-fetch';
import { connectDB } from '../config/db.js';
import { extractRootDomain } from '../services/dns.service.js';
import logger from '../config/logger.js';
import { cacheService } from '../services/cache.service.js';

// src/controllers/whois.controller.js
export async function getWhoisData(req, res) {
  const { domain, emailId } = req.params;
  const rootDomain = extractRootDomain(domain);
  
  logger.info(`Using root domain for WHOIS lookup: ${rootDomain}`);

  try {
    // First check MongoDB cache
    const db = await connectDB();
    const whoisCollection = db.collection('whois');
    
    // Look for cached entry that's less than 30 days old
    const cachedWhois = await whoisCollection.findOne({
      domain: rootDomain,
      createdAt: { 
        $gt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) 
      }
    });

    let whoisData;
    if (cachedWhois) {
      logger.info(`Found cached WHOIS data for ${rootDomain}`);
      whoisData = cachedWhois.data;
    } else {
      // Fetch from WHOIS API if not in DB
      whoisData = await fetchWhoisData(`http://localhost:8081/${rootDomain}`);
      
      // Store in MongoDB
      await whoisCollection.insertOne({
        domain: rootDomain,
        data: whoisData,
        createdAt: new Date()
      });
      
      logger.info(`Cached new WHOIS data for ${rootDomain}`);
    }

    // Update email if emailId provided
    if (emailId) {
      await updateDatabaseWithWhois(emailId, whoisData);
    }

    res.json({
      success: true,
      emailId,
      rootDomain,
      whoisData
    });

  } catch (error) {
    logger.error('Error processing WHOIS data:', error);
    res.status(500).json({ error: 'Error processing WHOIS data' });
  }
}
export async function postWhoisData(req, res) {
  const { domain } = req.body;
  const whoisApiUrl = `http://localhost:8081/${domain}`;

  try {
    const whoisData = await fetchWhoisData(whoisApiUrl);
    
    // Save to database
    const db = await connectDB();
    const whoisCollection = db.collection('whois');
    
    const result = await whoisCollection.insertOne({
      domain,
      whoisData,
      createdAt: new Date()
    });

    res.json({
      success: true,
      id: result.insertedId,
      whoisData
    });
  } catch (error) {
    logger.error('Error in POST WHOIS data:', error);
    res.status(500).json({ error: 'Error saving WHOIS data' });
  }
}

// Helper function to fetch WHOIS data
async function fetchWhoisData(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`WHOIS API error: ${response.statusText}`);
  }
  return response.json();
}

// Helper function to update database with WHOIS data
async function updateDatabaseWithWhois(emailId, whoisData) {
  const db = await connectDB();
  const emailsCollection = db.collection('emails');
  
  const updateResult = await emailsCollection.updateOne(
    { id: emailId },
    { 
      $set: { 
        'sender.whoisData': whoisData,
        'whoisLastUpdated': new Date()
      }
    }
  );
  
  if (updateResult.modifiedCount > 0) {
    logger.info(`[${new Date().toISOString()}] Updated WHOIS data for emailId: ${emailId}`);
  } else {
    logger.info(`[${new Date().toISOString()}] No email found or no changes made for emailId: ${emailId}`);
  }
  
  return updateResult;
}