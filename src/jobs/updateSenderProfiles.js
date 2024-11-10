import { connectDB } from '../config/db.js';
import { saveOrUpdateSenderProfile } from '../services/senderProfile.service.js';
import { senderLanguageProfileService } from '../services/senderLanguageProfile.service.js';
import logger from '../config/logger.js';

export async function processUnprocessedEmails() {
    const db = await connectDB();
    logger.info('Starting sender profile update job');

    try {
        // Check database state before processing
        const beforeState = await db.collection('emails').aggregate([
            {
                $group: {
                    _id: null,
                    total: { $sum: 1 },
                    unprocessedSender: {
                        $sum: { $cond: [{ $ne: ['$senderProfileProcessed', true] }, 1, 0] }
                    },
                    unprocessedLanguage: {
                        $sum: { $cond: [{ $ne: ['$languageProfileProcessed', true] }, 1, 0] }
                    }
                }
            }
        ]).toArray();
        
        logger.info('Database state before processing:', beforeState[0]);

        // Log the query we're using
        logger.info('Querying for unprocessed emails with criteria:', {
            senderProfileProcessed: { $ne: true },
            languageProfileProcessed: { $ne: true }
        });

        const unprocessedEmails = await db.collection('emails')
            .find({ 
                $or: [
                    { senderProfileProcessed: { $ne: true } },
                    { languageProfileProcessed: { $ne: true } }
                ]
            })
            .toArray();

        // Log more details about found emails
        logger.info(`Found ${unprocessedEmails.length} unprocessed emails`, {
            emailIds: unprocessedEmails.map(e => e.id),
            senders: unprocessedEmails.map(e => e.sender.address)
        });
        
        if (unprocessedEmails.length === 0) {
            logger.info('No unprocessed emails found');
            return;
        }

        const emailsBySender = unprocessedEmails.reduce((acc, email) => {
            const senderEmail = email.sender.address;
            if (!acc[senderEmail]) {
                acc[senderEmail] = [];
            }
            acc[senderEmail].push(email);
            return acc;
        }, {});

        // Process each sender's emails
        for (const [senderEmail, emails] of Object.entries(emailsBySender)) {
            try {
                logger.info(`Processing ${emails.length} emails for sender: ${senderEmail}`);

                // Update sender profile first
                const senderProfile = await saveOrUpdateSenderProfile(emails[0]);
                logger.info(`Updated sender profile for ${senderEmail}`);

                // Explicitly run language analysis
                logger.info(`Starting language analysis for ${senderEmail}`);
                const languageProfile = await senderLanguageProfileService.analyzeSenderEmails(senderEmail, emails);
                logger.info(`Completed language analysis for ${senderEmail}`, { 
                    wordCount: Object.keys(languageProfile.wordFrequency).length,
                    averageSentenceLength: languageProfile.averageSentenceLength
                });

                // Mark emails as processed only after both profiles are updated
                const emailIds = emails.map(email => email._id);
                await db.collection('emails').updateMany(
                    { _id: { $in: emailIds } },
                    { 
                        $set: { 
                            senderProfileProcessed: true,
                            languageProfileProcessed: true
                        }
                    }
                );

                logger.info(`Successfully processed all profiles for sender: ${senderEmail}`);
            } catch (error) {
                logger.error(`Error processing profiles for sender ${senderEmail}:`, error);
                continue;
            }
        }

        // Check database state after processing
        const afterState = await db.collection('emails').aggregate([
            {
                $group: {
                    _id: null,
                    total: { $sum: 1 },
                    unprocessedSender: {
                        $sum: { $cond: [{ $ne: ['$senderProfileProcessed', true] }, 1, 0] }
                    },
                    unprocessedLanguage: {
                        $sum: { $cond: [{ $ne: ['$languageProfileProcessed', true] }, 1, 0] }
                    }
                }
            }
        ]).toArray();
        
        logger.info('Database state after processing:', afterState[0]);
        logger.info('Completed sender profile update job');
    } catch (error) {
        logger.error('Error in sender profile update job:', error);
    }
} 