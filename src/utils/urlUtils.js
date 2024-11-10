// src/utils/urlUtils.js
import URLParse from 'url-parse';
import psl from 'psl';
import fetch from 'node-fetch';
import logger from '../config/logger.js';

export function parseUrl(urlString) {
    try {
        if (!urlString.startsWith('http')) {
            urlString = 'https://' + urlString;
        }
        
        const parsed = new URLParse(urlString);
        return {
            full: parsed.href,
            protocol: parsed.protocol,
            hostname: parsed.hostname,
            pathname: parsed.pathname,
            query: parsed.query,
            domain: extractDomain(parsed.hostname)
        };
    } catch (error) {
        logger.error('URL parsing error:', error);
        return null;
    }
}

export function extractDomain(hostname) {
    try {
        const parsed = psl.parse(hostname);
        return parsed.domain || hostname;
    } catch (error) {
        logger.error('Domain extraction error:', error);
        return hostname;
    }
}

export function normalizeUrl(url) {
    try {
        url = url.trim()
            .replace(/['"<>]/g, '')
            .split(/[|\s]/)[0]
            .replace(/&amp;/g, '&')
            .replace(/\/$/, '');

        if (!url.startsWith('http')) {
            url = 'https://' + url;
        }

        const parsed = new URL(url);
        return parsed.href;
    } catch {
        return url.toLowerCase();
    }
}

export function isValidUrl(url) {
    try {
        new URL(url);
        return true;
    } catch {
        return false;
    }
}

export function looksLikeUrl(text) {
    const urlPattern = /^(https?:\/\/)?[\w\-.]+(\.[\w\-.]+)+[^\s]*$/i;
    return urlPattern.test(text);
}

export function isValidDomain(domain) {
    return psl.isValid(domain);
}

export function getDomainInfo(url) {
    try {
        const hostname = url.replace(/^(https?:\/\/)?(www\.)?/, '');
        const parsed = psl.parse(hostname);
        return {
            domain: parsed.domain,
            subdomain: parsed.subdomain,
            tld: parsed.tld,
            listed: parsed.listed
        };
    } catch (error) {
        logger.error('Error getting domain info:', error);
        return {
            domain: hostname,
            subdomain: null,
            tld: null,
            listed: false
        };
    }
}

export function detectUrlMismatches(htmlContent) {
    const mismatches = [];
    const anchorRegex = /<a[^>]+href=["']([^"']+)["'][^>]*>([^<]+)<\/a>/g;
    let match;
    
    while ((match = anchorRegex.exec(htmlContent)) !== null) {
        const href = match[1].trim();
        const displayText = match[2].trim();
        
        if (looksLikeUrl(displayText)) {
            const normalizedHref = extractDomain(normalizeUrl(href));
            const normalizedDisplay = extractDomain(normalizeUrl(displayText));
            
            if (normalizedHref !== normalizedDisplay) {
                mismatches.push({
                    displayedUrl: displayText,
                    actualUrl: href,
                    suspicious: true
                });
            }
        }
    }
    
    return mismatches;
}

export function extractUrlsFromHtml(htmlContent) {
    try {
        const hrefRegex = /href=["'](https?:\/\/[^"']+)["']/g;
        const hrefMatches = [...htmlContent.matchAll(hrefRegex)].map(match => match[1]);
        
        const anchorRegex = />https?:\/\/[^<\s]+</g;
        const anchorMatches = [...htmlContent.matchAll(anchorRegex)]
            .map(match => match[0].slice(1, -1));
        
        const mismatches = detectUrlMismatches(htmlContent);
        
        const allUrls = [...new Set([...hrefMatches, ...anchorMatches])]
            .map(url => ({
                url: normalizeUrl(url),
                suspicious: false
            }))
            .filter(urlObj => isValidUrl(urlObj.url));

        return [...allUrls, ...mismatches];
    } catch (error) {
        logger.error('Error extracting URLs from HTML:', error);
        return [];
    }
}

export function extractUrlsFromText(text) {
    try {
        if (typeof text !== 'string') {
            logger.error('extractUrlsFromText received non-string input:', typeof text);
            return [];
        }
        
        const urlRegex = /(https?:\/\/[^\s<>"]+)/g;
        const matches = text.match(urlRegex) || [];
        
        return matches.map(url => ({
            url: normalizeUrl(url),
            suspicious: false
        })).filter(urlObj => isValidUrl(urlObj.url));
    } catch (error) {
        logger.error('Error extracting URLs from text:', error);
        return [];
    }
}

export async function checkUrlsWithSafeBrowsing(urls) {
    try {
        const API_KEY = process.env.SAFE_BROWSING_API_KEY;
        if (!API_KEY) {
            logger.error('Missing Google Safe Browsing API key');
            return [];
        }

        const response = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEY}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                client: {
                    clientId: "PhishFinder",
                    clientVersion: "1.0.0"
                },
                threatInfo: {
                    threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    platformTypes: ["ANY_PLATFORM"],
                    threatEntryTypes: ["URL"],
                    threatEntries: urls.map(url => ({ url }))
                }
            })
        });

        const data = await response.json();
        return data.matches || [];
    } catch (error) {
        logger.error('Error checking URLs with Safe Browsing:', error);
        return [];
    }
}

// For backward compatibility with existing imports
export default {
    parseUrl,
    extractDomain,
    normalizeUrl,
    isValidUrl,
    looksLikeUrl,
    isValidDomain,
    getDomainInfo,
    detectUrlMismatches,
    extractUrlsFromHtml,
    extractUrlsFromText,
    checkUrlsWithSafeBrowsing
};