import { processUnprocessedEmails } from './updateSenderProfiles.js';
import logger from '../config/logger.js';

export function startBackgroundJobs() {
    // Run immediately on startup
    processUnprocessedEmails().catch(error => {
        logger.error('Error in initial sender profile processing:', error);
    });

    // Schedule to run every 5 minutes
    setInterval(() => {
        processUnprocessedEmails().catch(error => {
            logger.error('Error in scheduled sender profile processing:', error);
        });
    }, 5 * 60 * 1000); // 5 minutes in milliseconds

    logger.info('Background jobs scheduled successfully');
} 