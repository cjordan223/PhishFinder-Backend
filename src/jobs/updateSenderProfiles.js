import { connectDB } from '../config/db.js';
import { saveOrUpdateSenderProfile } from '../services/senderProfile.service.js';
import logger from '../config/logger.js';

export async function processUnprocessedEmails() {
    const db = await connectDB();
    logger.info('Starting sender profile update job');

    try {
        // Find emails that haven't been processed for sender profiles
        const unprocessedEmails = await db.collection('emails')
            .find({ 
                senderProfileProcessed: { $ne: true }
            })
            .toArray();

        logger.info(`Found ${unprocessedEmails.length} unprocessed emails`);

        for (const email of unprocessedEmails) {
            try {
                // Map the email data to match expected structure
                const mappedEmailData = {
                    id: email.id,
                    sender: email.sender,
                    subject: email.subject,
                    timestamp: email.timestamp,
                    metadata: {
                        date: email.timestamp,
                        labels: email.behavioral?.labels || [],
                    },
                    raw: {
                        historyId: email.metadata?.historyId,
                        sizeEstimate: email.metadata?.sizeEstimate
                    },
                    body: email.content?.cleanedBody,
                    extractedUrls: email.content?.metrics?.extractedUrls || [],
                    security: {
                        analysis: {
                            isFlagged: email.security?.flags?.safebrowsingFlag || 
                                      email.security?.flags?.hasSuspiciousPatterns || 
                                      email.security?.flags?.hasUrlMismatches,
                            suspiciousKeywords: [], // Add if available in your data
                            linkRisks: email.content?.metrics?.urlMismatches || [],
                            safeBrowsingResult: [] // Add if available in your data
                        },
                        authentication: {
                            spf: email.security?.authentication?.spf?.record,
                            dkim: email.security?.authentication?.dkim?.record,
                            dmarc: email.security?.authentication?.dmarc?.record,
                            summary: `SPF: ${email.security?.authentication?.spf?.status || 'unknown'}, 
                                    DKIM: ${email.security?.authentication?.dkim?.status || 'unknown'}, 
                                    DMARC: ${email.security?.authentication?.dmarc?.policy || 'unknown'}`
                        }
                    }
                };

                await saveOrUpdateSenderProfile(mappedEmailData);
                
                // Mark email as processed
                await db.collection('emails').updateOne(
                    { _id: email._id },
                    { $set: { senderProfileProcessed: true }}
                );

                logger.info(`Processed sender profile for email ID: ${email.id}`);
            } catch (error) {
                logger.error(`Error processing sender profile for email ${email.id}:`, error);
                // Continue with next email even if one fails
            }
        }

        logger.info('Completed sender profile update job');
    } catch (error) {
        logger.error('Error in sender profile update job:', error);
    }
} 