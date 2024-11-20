import { processUnprocessedEmails } from './updateSenderProfiles.js';
import { updateRiskScores } from './updateRiskScores.js';
import logger from '../config/logger.js';

export function startBackgroundJobs() {
    // Run both jobs on startup
    processUnprocessedEmails();
    updateRiskScores();

    // Schedule jobs
    setInterval(processUnprocessedEmails, 5 * 60 * 1000);  // Every 5 minutes
    setInterval(updateRiskScores, 5 * 60 * 1000);         // Every 5 minutes

    logger.info('Background jobs scheduled');
}