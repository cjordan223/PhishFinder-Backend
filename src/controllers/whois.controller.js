// src/controllers/whois.controller.js
import fetch from 'node-fetch';
import { connectDB } from '../config/db.js';

export async function getWhoisData(req, res) {
  const { domain, emailId } = req.params;
  const method = req.method;
  console.log(`[${new Date().toISOString()}] ${method} WHOIS request for domain: ${domain}${emailId ? `, emailId: ${emailId}` : ''}`);

  const whoisApiUrl = `http://localhost:8081/${domain}`;

  try {
    const whoisData = await fetchWhoisData(whoisApiUrl);
    
    if (emailId) {
      // Update the existing email record with WHOIS data
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
        console.log(`[${new Date().toISOString()}] Updated WHOIS data for emailId: ${emailId}`);
      } else {
        console.log(`[${new Date().toISOString()}] No email found for emailId: ${emailId}`);
      }
    }

    console.log(`[${new Date().toISOString()}] Successfully fetched WHOIS data for ${domain}`);
    console.log(`[${new Date().toISOString()}] WHOIS data:`, whoisData);
    res.json({
      success: true,
      emailId,
      whoisData
    });
  } catch (error) {
    console.error(`[${new Date().toISOString()}] Error processing WHOIS data:`, error);
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
    console.error('Error in POST WHOIS data:', error);
    res.status(500).json({ error: 'Error saving WHOIS data' });
  }
}

// Helper functions
async function fetchWhoisData(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`WHOIS API error: ${response.statusText}`);
  }
  return response.json();
}

async function updateEmailRecord(emailId, whoisData) {
  const db = await connectDB();
  const emailsCollection = db.collection('emails');
  
  await emailsCollection.updateOne(
    { id: emailId },
    { 
      $set: { 
        whoisData,
        whoisLastUpdated: new Date()
      }
    }
  );
}