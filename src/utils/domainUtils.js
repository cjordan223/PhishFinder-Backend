// src/utils/domainUtils.js

// general functions to assist with domain parsing

import psl from 'psl';
// PSL is a library for parsing and validating domain names, more powerful than hand written regex

export function extractRootDomain(url) {
    try {
        // Remove protocol and get hostname
        const hostname = url.replace(/^(https?:\/\/)?(www\.)?/, '');
        
        // Parse using PSL
        const parsed = psl.parse(hostname);
        
        if (parsed.domain === null) {
            console.warn(`[DomainUtils] Could not parse domain from: ${url}`);
            return hostname;
        }
        
        console.log(`[DomainUtils] Extracted ${parsed.domain} from ${url}`);
        return parsed.domain;
    } catch (error) {
        console.error(`[DomainUtils] Error parsing domain from ${url}:`, error);
        return url;
    }
}

// Optional: Add more domain-related utilities
export function isValidDomain(domain) {
    return psl.isValid(domain);
}

export function getDomainInfo(url) {
    const hostname = url.replace(/^(https?:\/\/)?(www\.)?/, '');
    return psl.parse(hostname);
}