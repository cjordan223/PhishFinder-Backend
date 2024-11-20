// src/utils/urlUtils.js
import * as cheerio from 'cheerio';
import URLParse from 'url-parse';
import fetch from 'node-fetch';
import psl from 'psl';
import logger from '../config/logger.js';
import urlRegexSafe from 'url-regex-safe';
import ipRegex from 'ip-regex';
import validator from 'validator';


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
        if (ipRegex({exact: true}).test(hostname)) {
            return hostname;
        }
        const parsed = psl.parse(hostname);
        return parsed.domain || hostname;
    } catch (error) {
        logger.error('Domain extraction error:', error);
        return hostname;
    }
}

export function normalizeUrl(url) {
    try {
        if (typeof url !== 'string') {
            return '';
        }
        
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
    } catch (error) {
        logger.error('URL normalization error:', error);
        return url.toLowerCase();
    }
}

export function isValidUrl(url) {
    try {
        new URL(url);
        const hostname = new URL(url).hostname;
        return psl.isValid(hostname) || ipRegex().test(hostname);
    } catch (error) {
        return false;
    }
}

export function looksLikeUrl(text) {
    const urlPattern = /^(https?:\/\/)?([\w\-.]+\.[a-z]{2,}|(?:\d{1,3}\.){3}\d{1,3})(:\d+)?([/?#].*)?$/i;
    return urlPattern.test(text);
}

export function isValidDomain(domain) {
    return ipRegex().test(domain) || psl.isValid(domain);
}

export function getDomainInfo(url) {
    try {
        const hostname = url.replace(/^(https?:\/\/)?(www\.)?/, '');
        
        if (ipRegex().test(hostname)) {
            return {
                domain: hostname,
                subdomain: null,
                tld: null,
                listed: false,
                isIP: true
            };
        }

        const parsed = psl.parse(hostname);
        return {
            domain: parsed.domain,
            subdomain: parsed.subdomain,
            tld: parsed.tld,
            listed: parsed.listed,
            isIP: false
        };
    } catch (error) {
        logger.error('Error getting domain info:', error);
        return {
            domain: url,
            subdomain: null,
            tld: null,
            listed: false,
            isIP: false
        };
    }
}

export function detectUrlMismatches(htmlContent) {
    try {
        const $ = cheerio.load(htmlContent);
        const mismatches = [];

        $('a[href]').each((index, element) => {
            const displayedText = $(element).text().trim();
            const actualUrl = $(element).attr('href').trim();

            if (displayedText && actualUrl) {
                try {
                    let displayDomain = '';
                    let actualDomain = '';

                    // Check if displayedText is a URL
                    if (validator.isURL(displayedText, { require_protocol: true })) {
                        displayDomain = new URL(displayedText).hostname;
                    }
                    // Check if displayedText is an email
                    else if (validator.isEmail(displayedText)) {
                        displayDomain = displayedText.split('@')[1];
                    } else {
                        // Skip if displayedText is neither a URL nor an email
                        return;
                    }

                    // Parse actualUrl
                    if (actualUrl.startsWith('mailto:')) {
                        const email = actualUrl.replace('mailto:', '');
                        actualDomain = email.split('@')[1];
                    } else {
                        actualDomain = new URL(actualUrl).hostname;
                    }

                    // Compare domains
                    if (displayDomain !== actualDomain) {
                        mismatches.push({
                            displayedUrl: displayedText,
                            actualUrl,
                            displayDomain,
                            actualDomain,
                            suspicious: true
                        });
                    }
                } catch (e) {
                    logger.error('Error parsing URL:', e);
                }
            }
        });

        return mismatches;
    } catch (error) {
        logger.error('Error detecting URL mismatches:', error);
        return [];
    }
}

export function extractUrlsFromHtml(htmlContent) {
    try {
        const $ = cheerio.load(htmlContent);
        const urls = new Set();

        // Extract URLs from href attributes
        $('a[href]').each((_, element) => {
            const href = $(element).attr('href');
            if (href && isValidUrl(href)) {
                urls.add(normalizeUrl(href));
            }
        });

        // Extract URLs from text content
        const textContent = $.text();
        const textUrls = extractUrlsFromText(textContent);
        textUrls.forEach(({url}) => urls.add(url));

        return Array.from(urls).map(url => {
            try {
                const hostname = new URL(url).hostname;
                return {
                    url,
                    suspicious: ipRegex().test(hostname)
                };
            } catch (error) {
                return { url, suspicious: false };
            }
        });
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

        const urlPattern = urlRegexSafe({ strict: true, ipv4: true });
        const matches = text.match(urlPattern) || [];

        return matches.map(url => {
            try {
                const normalizedUrl = normalizeUrl(url);
                const hostname = new URL(normalizedUrl).hostname;
                return {
                    url: normalizedUrl,
                    suspicious: ipRegex().test(hostname)
                };
            } catch (error) {
                return {
                    url,
                    suspicious: false
                };
            }
        }).filter(({url}) => isValidUrl(url));
    } catch (error) {
        logger.error('Error extracting URLs from text:', error);
        return [];
    }
}

export async function checkUrlsWithSafeBrowsing(urls) {
    try {
        const API_KEY = process.env.SAFE_BROWSING_API_KEY;
        if (!API_KEY) {
            logger.safeBrowsing('Missing Google Safe Browsing API key');
            return urls.map(url => ({ url, suspicious: false }));
        }

        logger.safeBrowsing('Checking URLs with Safe Browsing API', { urlCount: urls.length });

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
        
        // Create a map of threatened URLs
        const threatenedUrls = new Set(
            (data.matches || []).map(match => match.threat.url)
        );

        const results = urls.map(url => ({
            url,
            suspicious: threatenedUrls.has(url)
        }));

        logger.safeBrowsing('Safe Browsing API check completed', {
            checkedUrls: urls.length,
            threatenedUrls: threatenedUrls.size,
            results
        });

        return results;

    } catch (error) {
        logger.safeBrowsing('Error checking URLs with Safe Browsing', {
            error: error.message,
            stack: error.stack
        });
        return urls.map(url => ({ url, suspicious: false }));
    }
}

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