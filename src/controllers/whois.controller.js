// src/controllers/whois.controller.js
import fetch from 'node-fetch';
import { connectDB } from '../config/db.js';
import { extractRootDomain } from '../services/dns.service.js';
import logger from '../config/logger.js';
import { cacheService } from '../services/cache.service.js';

export async function getWhoisData(req, res) {
  const { domain, emailId } = req.params;
  const method = req.method;
  
  // Extract root domain for WHOIS lookup
  const rootDomain = extractRootDomain(domain);
  
  logger.info(`[${new Date().toISOString()}] Incoming ${method} request to /whois/${domain}${emailId ? `/${emailId}` : ''}`);
  logger.info(`[${new Date().toISOString()}] Using root domain for WHOIS lookup: ${rootDomain}`);

  try {
    // Check cache first
    const cacheKey = `whois:${rootDomain}`;
    let whoisData = cacheService.get(cacheKey);

    if (!whoisData) {
      // Fetch WHOIS data using root domain
      whoisData = await fetchWhoisData(`http://localhost:8081/${rootDomain}`);
      logger.info(`[${new Date().toISOString()}] Successfully fetched WHOIS data for ${rootDomain}`);
      logger.info(`[${new Date().toISOString()}] WHOIS data:`, whoisData);

      // Cache the WHOIS data
      cacheService.set(cacheKey, whoisData);
    } else {
      logger.info(`[${new Date().toISOString()}] Cache hit for WHOIS data: ${rootDomain}`);
    }

    // Update database if emailId is provided
    if (emailId) {
      await updateDatabaseWithWhois(emailId, whoisData);
    } else {
      logger.info(`[${new Date().toISOString()}] No emailId provided - skipping database update`);
    }

    // Return response
    res.json({
      success: true,
      emailId,
      originalDomain: domain,
      rootDomain,
      whoisData
    });
  } catch (error) {
    logger.error(`[${new Date().toISOString()}] Error processing WHOIS data:`, error);
    res.status(500).json({ 
      error: 'Error processing WHOIS data',
      originalDomain: domain,
      rootDomain
    });
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