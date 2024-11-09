import { processUnprocessedEmails } from './updateSenderProfiles.js';
import logger from '../config/logger.js';

// this file exists to handle the creation of background jobs
// right now it only handles the processing of sender profiles
// in the future it could be expanded to handle other tasks

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