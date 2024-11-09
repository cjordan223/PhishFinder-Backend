import { connectDB } from '../config/db.js';
import { saveOrUpdateSenderProfile } from '../services/senderProfile.service.js';
import { senderLanguageProfileService } from '../services/senderLanguageProfile.service.js';
import logger from '../config/logger.js';

export async function processUnprocessedEmails() {
    const db = await connectDB();
    logger.info('Starting sender profile update job');

    try {
        const unprocessedEmails = await db.collection('emails')
            .find({ 
                senderProfileProcessed: { $ne: true }
            })
            .toArray();

        logger.info(`Found ${unprocessedEmails.length} unprocessed emails`);
        
        if (unprocessedEmails.length === 0) {
            logger.info('No unprocessed emails found');
            return;
        }

        // Group emails by sender
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
                // Update sender profile
                await saveOrUpdateSenderProfile(emails[0]); // Use first email for basic profile
                
                // Update language profile
                await senderLanguageProfileService.analyzeSenderEmails(senderEmail, emails);

                // Mark emails as processed
                const emailIds = emails.map(email => email._id);
                await db.collection('emails').updateMany(
                    { _id: { $in: emailIds } },
                    { $set: { senderProfileProcessed: true }}
                );

                logger.info(`Processed profiles for sender: ${senderEmail}`);
            } catch (error) {
                logger.error(`Error processing profiles for sender ${senderEmail}:`, error);
                continue;
            }
        }

        logger.info('Completed sender profile update job');
    } catch (error) {
        logger.error('Error in sender profile update job:', error);
    }
} 