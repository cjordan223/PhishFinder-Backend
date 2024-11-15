// New file:  src/utils/receiverUtils.js
import logger from '../config/logger.js';

export function extractDisplayName(emailString) {
    if (!emailString) return null;
    try {
        const match = emailString.match(/^"?([^"<]+)"?\s*<?([^>]*)>?$/);
        if (match && match[1]) {
            return match[1].trim();
        }
        return null;
    } catch (error) {
        logger.error('Error extracting display name:', error);
        return null;
    }
}

export function extractDomain(emailString) {
    if (!emailString) return null;
    try {
        const match = emailString.match(/@([^>]+)>?$/);
        if (match && match[1]) {
            return match[1].trim();
        }
        return null;
    } catch (error) {
        logger.error('Error extracting domain:', error);
        return null;
    }
}

export function parseRecipients(emailString) {
    if (!emailString) return [];
    try {
        return emailString
            .split(',')
            .map(email => {
                const address = email.trim();
                return {
                    address,
                    displayName: extractDisplayName(address),
                    domain: extractDomain(address)
                };
            })
            .filter(recipient => recipient.address);
    } catch (error) {
        logger.error('Error parsing recipients:', error);
        return [];
    }
}