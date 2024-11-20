import { connectDB } from '../config/db.js';
import { riskScoreService } from '../services/riskScore.service.js';
import logger from '../config/logger.js';

export async function updateRiskScores() {
    const db = await connectDB();
    logger.info('Starting risk score update job');

    try {
        // Find emails without risk scores
        const unprocessedEmails = await db.collection('emails')
            .find({ 
                'security.authentication.riskScore': { $exists: false }
            })
            .toArray();

        logger.info(`Found ${unprocessedEmails.length} emails needing risk scores`);

        let updatedCount = 0;
        for (const email of unprocessedEmails) {
            try {
                const riskScore = riskScoreService.calculateRiskScore(email);
                await db.collection('emails').updateOne(
                    { _id: email._id },
                    { 
                        $set: { 
                            'security.authentication.riskScore': riskScore 
                        }
                    }
                );
                updatedCount++;
            } catch (error) {
                logger.error(`Error updating risk score for email ${email.id}:`, error);
            }
        }

        logger.info(`Updated risk scores for ${updatedCount} emails`);
    } catch (error) {
        logger.error('Error in risk score update job:', error);
    }
}