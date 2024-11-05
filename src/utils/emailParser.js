/**
 * Extracts organization name from email domain and content
 * @param {string} domain - Email domain
 * @param {string} body - Cleaned email body
 * @returns {string|null} - Extracted organization name or null
 */
function extractOrganization(domain, body) {
    try {
        // First check common email service providers
        const commonProviders = [
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 
            'aol.com', 'icloud.com', 'protonmail.com'
        ];
        
        if (commonProviders.includes(domain.toLowerCase())) {
            return null; // Personal email, no organization
        }

        // Try to extract from domain first
        let org = domain
            .split('.')[0] // Get first part of domain
            .replace(/(-|_)/g, ' ') // Replace dashes and underscores with spaces
            .split(/(?=[A-Z])/).join(' ') // Split on camelCase
            .replace(/\b\w/g, l => l.toUpperCase()); // Capitalize first letter of each word

        // If domain is likely an organization name, return it
        if (org.length > 3 && !commonProviders.includes(domain)) {
            return org;
        }

        // Look for common organization indicators in email body
        const orgIndicators = [
            // Company/org name followed by common department names
            /([A-Z][A-Za-z0-9\s&.,]+)\s+(Corporation|Inc|LLC|Ltd|Company|Department|Team)/,
            // Common email signature patterns
            /(?:From|Sent from|Regards|Sincerely),?\s*([A-Z][A-Za-z0-9\s&.,]+)/,
            // Letter head patterns
            /^([A-Z][A-Za-z0-9\s&.,]+)\s+(Headquarters|Office|Building)/m
        ];

        for (const pattern of orgIndicators) {
            const match = body.match(pattern);
            if (match && match[1]) {
                // Clean up extracted name
                const extracted = match[1]
                    .trim()
                    .replace(/\s+/g, ' ')
                    .replace(/[^\w\s&.,]/g, '');
                
                // Verify it's a reasonable length and format
                if (extracted.length > 3 && extracted.length < 50) {
                    return extracted;
                }
            }
        }

        // If no clear organization found, return domain-based guess
        return org.length > 3 ? org : null;

    } catch (err) {
        console.error('Error extracting organization:', err);
        return null;
    }
}

// Additional helper to clean organization names
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

// Export both functions
export { extractOrganization, cleanOrgName }; 