import logger from '../config/logger.js';
import UrlUtils from './urlUtils.js';
import { cleanEmailBody, extractReadableText } from './textCleaner.js';

/**
 * Extracts organization name from email domain and content
 * @param {string} domain - Email domain
 * @param {string} body - Cleaned email body
 * @returns {string|null} - Extracted organization name or null
 */
function extractOrganization(domain, body) {
    try {
        const cleanedBody = cleanEmailBody(body);
        const readableText = extractReadableText(cleanedBody);
        
        // First check common email service providers
        const commonProviders = [
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 
            'aol.com', 'icloud.com', 'protonmail.com'
        ];
        
        if (commonProviders.includes(domain?.toLowerCase())) {
            return null; // Personal email, no organization
        }

        // Try to extract from domain first
        let org = UrlUtils.extractDomain(domain)
            .split('.')[0]
            .replace(/[-_]/g, ' ') // Using character class instead of alternation
            .split(/(?=[A-Z])/).join(' ')
            .replace(/\b\w/g, l => l.toUpperCase());

        // If domain is likely an organization name, return it
        if (org.length > 3 && !commonProviders.includes(domain)) {
            return cleanOrgName(org);
        }

        // Look for common organization indicators in email body
        const orgIndicators = [
            /([A-Z][A-Za-z0-9\s&.,]+)\s+(Corporation|Inc|LLC|Ltd|Company|Department|Team)/,
            /(?:From|Sent from|Regards|Sincerely),?\s*([A-Z][A-Za-z0-9\s&.,]+)/,
            /^([A-Z][A-Za-z0-9\s&.,]+)\s+(Headquarters|Office|Building)/m
        ];

        for (const pattern of orgIndicators) {
            const match = readableText?.match(pattern);
            if (match?.[1]) {
                const extracted = match[1]
                    .trim()
                    .replace(/\s+/g, ' ')
                    .replace(/[^\w\s&.,]/g, '');
                
                if (extracted.length > 3 && extracted.length < 50) {
                    return cleanOrgName(extracted);
                }
            }
        }

        return org.length > 3 ? cleanOrgName(org) : null;

    } catch (err) {
        logger.error('Error extracting organization:', err);
        return null;
    }
}

/**
 * Cleans organization names by removing common suffixes
 * @param {string} name - Organization name to clean
 * @returns {string|null} - Cleaned organization name or null
 */
function cleanOrgName(name) {
    if (!name) return null;
    
    // Remove common suffixes
    const suffixes = [
        'Inc', 'LLC', 'Ltd', 'Limited', 'Corp', 'Corporation',
        'Co', 'Company', 'Team', 'Department', 'Dept'
    ];
    
    let cleaned = name;
    suffixes.forEach(suffix => {
        cleaned = cleaned.replace(new RegExp(`\\s*${suffix}\\.?\\s*$`, 'i'), '');
    });

    return cleaned.trim();
}

export { extractOrganization, cleanOrgName };