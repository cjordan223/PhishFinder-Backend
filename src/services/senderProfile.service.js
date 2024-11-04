import { connectDB } from '../config/db.js'; // Importing the database connection function

//Don't remove it - it enables:

// Tracking sender reputation over time
// Identifying suspicious pattern changes
// Historical security metrics
// Future ML/AI analysis capabilities

// Helper functions to save or update the sender profile in the database

// Function to save or update sender profile in the database
export async function saveOrUpdateSenderProfile(emailData) {
  const db = await connectDB(); // Establish a connection to the database
  const senderEmail = emailData.sender.address; // Extract the sender's email address
  const domain = emailData.sender.domain; // Extract the sender's domain

  // Check if a profile already exists for the sender
  const profile = await db.collection('sender_profiles').findOne({ 
    'sender.address': senderEmail // Query to find the sender profile by email address
  });

  // Create an email entry object with relevant information
  const emailEntry = {
    // Basic Email Info
    id: emailData.id, // Unique identifier for the email
    subject: emailData.subject, // Subject of the email
    date: emailData.metadata.date, // Date the email was sent
    body: emailData.body, // Body content of the email
    extractedUrls: emailData.extractedUrls, // URLs extracted from the email content
    timestamp: new Date(emailData.timestamp), // Timestamp of the email

    // Email Metadata
    labels: emailData.metadata.labels, // Labels associated with the email
    historyId: emailData.raw.historyId, // History ID for tracking email changes
    sizeEstimate: emailData.raw.sizeEstimate, // Estimated size of the email

    // Security Analysis
    isFlagged: emailData.security.analysis.isFlagged, // Flag status of the email
    suspiciousKeywords: emailData.security.analysis.suspiciousKeywords, // Keywords flagged as suspicious
    linkRisks: emailData.security.analysis.linkRisks, // Risks associated with links in the email
    safeBrowsingResults: emailData.security.analysis.safeBrowsingResult, // Safe browsing results for links

    // Authentication Details
    authentication: {
      spf: emailData.security.authentication.spf, // SPF authentication result
      dkim: emailData.security.authentication.dkim, // DKIM authentication result
      dmarc: emailData.security.authentication.dmarc, // DMARC authentication result
      summary: emailData.security.authentication.summary // Summary of authentication results
    }
  };

  console.log('Attempting to save email entry:', JSON.stringify(emailEntry, null, 2)); // Log the email entry being saved

  // Security metrics for the sender profile
  const securityMetrics = {
    totalEmails: 1, // Total number of emails for this sender
    suspiciousEmails: emailData.security.analysis.isFlagged ? 1 : 0, // Count of flagged emails
    suspiciousLinkCount: emailData.security.analysis.linkRisks.filter(r => r.isSuspicious).length, // Count of suspicious links
    phishingLinkCount: emailData.security.analysis.linkRisks.filter(r => r.threatType === 'SOCIAL_ENGINEERING').length, // Count of phishing links
    unwantedSoftwareCount: emailData.security.analysis.linkRisks.filter(r => r.threatType === 'UNWANTED_SOFTWARE').length, // Count of unwanted software links
    suspiciousKeywordCount: emailData.security.analysis.suspiciousKeywords.reduce((acc, curr) => acc + curr.matches.length, 0) // Count of suspicious keywords
  };

  // If a profile already exists, update it
  if (profile) {
    const updateOperation = {
      $push: { emails: emailEntry }, // Add the new email entry to the existing profile
      $inc: securityMetrics, // Increment the security metrics
      $set: {
        lastUpdated: new Date(), // Update the last updated timestamp
        'sender.displayName': emailData.sender.displayName, // Update the sender's display name
        'sender.domain': domain, // Update the sender's domain
        lastAuthenticationStatus: {
          spf: emailData.security.authentication.spf, // Update SPF status
          dkim: emailData.security.authentication.dkim, // Update DKIM status
          dmarc: emailData.security.authentication.dmarc, // Update DMARC status
          summary: emailData.security.authentication.summary // Update authentication summary
        }
      }
    };
    
    console.log('Update operation:', JSON.stringify(updateOperation, null, 2)); // Log the update operation
    
    // Perform the update operation on the database
    await db.collection('sender_profiles').updateOne(
      { 'sender.address': senderEmail }, // Find the profile by sender's email
      updateOperation // Apply the update operation
    );
  } else {
    // If no profile exists, create a new one
    const newProfile = {
      sender: emailData.sender, // Store sender information
      emails: [emailEntry], // Initialize with the first email entry
      securityMetrics, // Store the security metrics
      created: new Date(), // Set the creation date
      lastUpdated: new Date(), // Set the last updated date
      lastAuthenticationStatus: {
        spf: emailData.security.authentication.spf, // Store SPF status
        dkim: emailData.security.authentication.dkim, // Store DKIM status
        dmarc: emailData.security.authentication.dmarc, // Store DMARC status
        summary: emailData.security.authentication.summary // Store authentication summary
      }
    };

    console.log('Creating new profile:', JSON.stringify(newProfile, null, 2)); // Log the new profile being created
    
    // Insert the new profile into the database
    await db.collection('sender_profiles').insertOne(newProfile);
  }
}