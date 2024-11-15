import { connectDB } from '../config/db.js';
import logger from '../config/logger.js';
import { cleanEmailBody, extractReadableText } from '../utils/textCleaner.js';


// Create helper functions outside the main function
function createEmailEntry(emailData) {
    return {
        id: emailData.id,
        subject: emailData.subject,
        timestamp: new Date(emailData.timestamp),
        body: extractReadableText(cleanEmailBody(emailData.content?.cleanedBody || '')),
        receiver: {
            address: emailData.receiver.address,
            displayName: emailData.receiver.displayName,
            domain: emailData.receiver.domain,
            cc: emailData.receiver.cc,
            bcc: emailData.receiver.bcc
        },
        isFlagged: emailData.security?.flags?.safebrowsingFlag || 
                   emailData.security?.flags?.hasSuspiciousPatterns || 
                   emailData.security?.flags?.hasUrlMismatches || false,
        authentication: buildAuthenticationObject(emailData.security?.authentication),
        labels: emailData.behavioral?.labels || [],
        sizeEstimate: emailData.metadata?.sizeEstimate
    };
}

function buildAuthenticationObject(auth = {}) {
    return {
        spf: auth?.spf?.record || null,
        dkim: auth?.dkim?.record || null,
        dmarc: auth?.dmarc?.record || null,
        summary: `SPF: ${auth?.spf?.status || 'unknown'}, 
                 DKIM: ${auth?.dkim?.status || 'unknown'}, 
                 DMARC: ${auth?.dmarc?.policy || 'unknown'}`
    };
}

export async function saveOrUpdateSenderProfile(emailData) {
    const db = await connectDB();
    const senderEmail = emailData.sender.address;
    const emailEntry = createEmailEntry(emailData);
    
    try {
        // Use updateOne with upsert instead of separate insert/update logic
        await db.collection('sender_profiles').updateOne(
            { 'sender.address': senderEmail },
            {
                $setOnInsert: {
                    sender: {
                        address: senderEmail,
                        displayName: emailData.sender.displayName,
                        domain: emailData.sender.domain,
                        firstSeen: new Date()
                    },
                    created: new Date()
                },
                $set: {
                    lastUpdated: new Date(),
                    lastAuthenticationStatus: emailEntry.authentication
                },
                $push: { 
                    emails: {
                        $each: [emailEntry],
                        $position: 0
                    }
                },
                $inc: {
                    'securityMetrics.totalEmails': 1,
                    'securityMetrics.suspiciousEmails': emailEntry.isFlagged ? 1 : 0,
                    'securityMetrics.suspiciousLinkCount': emailData.content?.metrics?.urlMismatches?.length || 0,
                    'securityMetrics.phishingLinkCount': emailData.security?.flags?.phishingLinks?.length || 0,
                    'securityMetrics.unwantedSoftwareCount': emailData.security?.flags?.malwareLinks?.length || 0,
                    'securityMetrics.suspiciousKeywordCount': emailData.security?.flags?.suspiciousPatterns?.length || 0
                }
            },
            { upsert: true }
        );

        return await db.collection('sender_profiles').findOne({ 'sender.address': senderEmail });
    } catch (error) {
        logger.error('Error saving sender profile:', error);
        throw error;
    }
}