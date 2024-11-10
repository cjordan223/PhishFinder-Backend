import { connectDB } from '../config/db.js';
import { saveOrUpdateSenderProfile } from './senderProfile.service.js';
import { senderLanguageProfileService } from './senderLanguageProfile.service.js';
import logger from '../config/logger.js';

export async function saveEmailAnalysis(emailData, processProfileImmediately = true) {
    const db = await connectDB();
    const emailsCollection = db.collection('emails');
    
    try {
        const existingEmail = await emailsCollection.findOne({ id: emailData.id });
        
        if (existingEmail) {
            logger.info(`Email with id ${emailData.id} already exists. Skipping insertion.`);
            return existingEmail._id;
        }

        const emailDataWithNull = {
            ...emailData,
            sender: {
                ...emailData.sender,
                whoisData: null
            },
            whoisLastUpdated: null,
            senderProfileProcessed: false,
            languageProfileProcessed: false
        };

        const result = await emailsCollection.insertOne(emailDataWithNull);
        logger.info(`Email analysis saved with ID: ${result.insertedId}`);

        if (processProfileImmediately) {
            try {
                // Update sender profile
                await saveOrUpdateSenderProfile(emailData);
                
                // Process language profile
                const emails = [emailData];
                await senderLanguageProfileService.analyzeSenderEmails(emailData.sender.address, emails);

                // Mark email as processed
                await emailsCollection.updateOne(
                    { _id: result.insertedId },
                    { 
                        $set: {
                            senderProfileProcessed: true,
                            languageProfileProcessed: true
                        }
                    }
                );

                logger.info(`Immediate profile processing completed for email ${emailData.id}`);
            } catch (profileError) {
                logger.error('Error in immediate profile processing:', profileError);
                // Don't throw the error - we still want to return the insertedId
            }
        }

        return result.insertedId;
    } catch (error) {
        logger.error('Error saving email analysis:', error);
        throw error;
    }
} 