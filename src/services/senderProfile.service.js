import { connectDB } from '../config/db.js';
import logger from '../config/logger.js';
import { cleanEmailBody, extractReadableText } from '../utils/textCleaner.js';

export async function saveOrUpdateSenderProfile(emailData) {
    const db = await connectDB();
    const senderEmail = emailData.sender.address;
    const domain = emailData.sender.domain;

    // Clean and prepare the email body
    const cleanedBody = cleanEmailBody(emailData.content?.cleanedBody || '');
    const readableText = extractReadableText(cleanedBody);

    const emailEntry = {
        id: emailData.id,
        subject: emailData.subject,
        timestamp: new Date(emailData.timestamp),
        body: readableText,
        isFlagged: emailData.security?.flags?.safebrowsingFlag || 
                   emailData.security?.flags?.hasSuspiciousPatterns || 
                   emailData.security?.flags?.hasUrlMismatches || false,
        authentication: {
            spf: emailData.security?.authentication?.spf?.record || null,
            dkim: emailData.security?.authentication?.dkim?.record || null,
            dmarc: emailData.security?.authentication?.dmarc?.record || null,
            summary: `SPF: ${emailData.security?.authentication?.spf?.status || 'unknown'}, 
                     DKIM: ${emailData.security?.authentication?.dkim?.status || 'unknown'}, 
                     DMARC: ${emailData.security?.authentication?.dmarc?.policy || 'unknown'}`
        },
        labels: emailData.behavioral?.labels || [],
        sizeEstimate: emailData.metadata?.sizeEstimate
    };

    const securityMetrics = {
        totalEmails: 1,
        suspiciousEmails: emailEntry.isFlagged ? 1 : 0,
        suspiciousLinkCount: emailData.content?.metrics?.urlMismatches?.length || 0,
        phishingLinkCount: 0,
        unwantedSoftwareCount: 0,
        suspiciousKeywordCount: emailData.security?.flags?.hasSuspiciousPatterns ? 1 : 0
    };

    try {
        await db.collection('sender_profiles').updateOne(
            { 'sender.address': senderEmail },
            {
                $push: { emails: emailEntry },
                $inc: securityMetrics,
                $set: {
                    lastUpdated: new Date(),
                    lastAuthenticationStatus: emailEntry.authentication
                },
                $setOnInsert: {
                    sender: {
                        address: senderEmail,
                        displayName: emailData.sender.displayName,
                        domain: domain
                    },
                    created: new Date()
                }
            },
            { upsert: true }
        );
    } catch (error) {
        logger.error('Error saving sender profile:', error);
        throw error;
    }
}