import { connectDB } from '../config/db.js';
import logger from '../config/logger.js';

export async function saveOrUpdateSenderProfile(emailData) {
  const db = await connectDB();
  const senderEmail = emailData.sender.address;
  const domain = emailData.sender.domain;

  // Check if profile exists
  const profile = await db.collection('sender_profiles').findOne({ 
    'sender.address': senderEmail 
  });

  // Create email entry with only the data we actually have
  const emailEntry = {
    // Basic Email Info
    id: emailData.id,
    subject: emailData.subject,
    timestamp: new Date(emailData.timestamp),
    
    // Content
    body: emailData.content?.cleanedBody,
    extractedUrls: emailData.content?.metrics?.extractedUrls || [],
    
    // Security Analysis
    isFlagged: emailData.security?.flags?.safebrowsingFlag || 
               emailData.security?.flags?.hasSuspiciousPatterns || 
               emailData.security?.flags?.hasUrlMismatches || false,
    
    // Authentication Details
    authentication: {
      spf: emailData.security?.authentication?.spf?.record || null,
      dkim: emailData.security?.authentication?.dkim?.record || null,
      dmarc: emailData.security?.authentication?.dmarc?.record || null,
      summary: `SPF: ${emailData.security?.authentication?.spf?.status || 'unknown'}, 
                DKIM: ${emailData.security?.authentication?.dkim?.status || 'unknown'}, 
                DMARC: ${emailData.security?.authentication?.dmarc?.policy || 'unknown'}`
    },

    // Metadata
    labels: emailData.behavioral?.labels || [],
    sizeEstimate: emailData.metadata?.sizeEstimate
  };

  logger.info('Attempting to save email entry:', JSON.stringify(emailEntry, null, 2));

  // Security metrics based on actual data
  const securityMetrics = {
    totalEmails: 1,
    suspiciousEmails: emailEntry.isFlagged ? 1 : 0,
    suspiciousLinkCount: emailData.content?.metrics?.urlMismatches?.length || 0,
    phishingLinkCount: 0, // Set to 0 as we don't have this data yet
    unwantedSoftwareCount: 0, // Set to 0 as we don't have this data yet
    suspiciousKeywordCount: emailData.security?.flags?.hasSuspiciousPatterns ? 1 : 0
  };

  if (profile) {
    const updateOperation = {
      $push: { emails: emailEntry },
      $inc: securityMetrics,
      $set: {
        lastUpdated: new Date(),
        'sender.displayName': emailData.sender.displayName,
        'sender.domain': domain,
        lastAuthenticationStatus: {
          spf: emailData.security?.authentication?.spf?.record || null,
          dkim: emailData.security?.authentication?.dkim?.record || null,
          dmarc: emailData.security?.authentication?.dmarc?.record || null,
          summary: emailEntry.authentication.summary
        }
      }
    };
    
    logger.info('Update operation:', JSON.stringify(updateOperation, null, 2));
    
    await db.collection('sender_profiles').updateOne(
      { 'sender.address': senderEmail },
      updateOperation
    );
  } else {
    const newProfile = {
      sender: emailData.sender,
      emails: [emailEntry],
      securityMetrics,
      created: new Date(),
      lastUpdated: new Date(),
      lastAuthenticationStatus: {
        spf: emailData.security?.authentication?.spf?.record || null,
        dkim: emailData.security?.authentication?.dkim?.record || null,
        dmarc: emailData.security?.authentication?.dmarc?.record || null,
        summary: emailEntry.authentication.summary
      }
    };

    logger.info('Creating new profile:', JSON.stringify(newProfile, null, 2));
    
    await db.collection('sender_profiles').insertOne(newProfile);
  }
}