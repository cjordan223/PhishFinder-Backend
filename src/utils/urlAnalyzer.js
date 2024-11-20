import { LinkChecker } from 'linkinator';
import logger from '../config/logger.js';
import UrlUtils from './urlUtils.js';
import { connectDB } from '../config/db.js';

class UrlAnalyzer {
    constructor() {
        this.linkChecker = new LinkChecker();
    }

    async analyzeUrl(displayText, href) {
        try {
            const analysis = {
                displayUrl: UrlUtils.parseUrl(displayText),
                actualUrl: UrlUtils.parseUrl(href),
                suspicious: false,
                reasons: [],
                redirects: [],
                security: {
                    ssl: false,
                    certificate: null,
                    safeBrowsing: null
                }
            };

            // Check for URL mismatches
            if (this.isDomainMismatch(analysis.displayUrl, analysis.actualUrl)) {
                analysis.suspicious = true;
                analysis.reasons.push('domain_mismatch');
            }

            // Check with Safe Browsing API
            const safeBrowsingResults = await UrlUtils.checkUrlsWithSafeBrowsing([href]);
            if (safeBrowsingResults.length > 0 && safeBrowsingResults[0].suspicious) {
                analysis.suspicious = true;
                analysis.reasons.push('safe_browsing_threat');
                analysis.security.safeBrowsing = safeBrowsingResults[0];
            }

            // Check for redirects
            const redirectChain = await this.checkRedirects(href);
            if (redirectChain.length > 1) {
                analysis.redirects = redirectChain;
                analysis.reasons.push('multiple_redirects');
            }

            logger.info('URL analysis result:', analysis);
            return analysis;

        } catch (error) {
            logger.error('URL analysis error:', error);
            return null;
        }
    }

    isDomainMismatch(displayUrl, actualUrl) {
        if (!displayUrl || !actualUrl) return false;
        return displayUrl.domain !== actualUrl.domain;
    }

    async checkRedirects(url) {
        try {
            const results = await this.linkChecker.check(url);
            return results.links
                .filter(link => link.status === 301 || link.status === 302)
                .map(link => link.url);
        } catch (error) {
            logger.error('Error checking redirects:', error);
            return [];
        }
    }

    async analyzeEmailBody(emailBody) {
        try {
            const urlsFromText = UrlUtils.extractUrlsFromText(emailBody);
            const urlsFromHtml = UrlUtils.extractUrlsFromHtml(emailBody);
            const allUrls = [...urlsFromText, ...urlsFromHtml];

            const flaggedUrls = [];
            const suspiciousPatterns = [];
            const urlMismatches = UrlUtils.detectUrlMismatches(emailBody);

            for (const urlObj of allUrls) {
                const analysis = await this.analyzeUrl(urlObj.url, urlObj.url);
                if (analysis.suspicious) {
                    flaggedUrls.push(analysis);
                }
                // Update the suspicious flag in the original URL object
                urlObj.suspicious = analysis.suspicious;
            }

            logger.info('Extracted URLs:', allUrls);
            logger.info('Flagged URLs:', flaggedUrls);
            logger.info('Suspicious patterns:', suspiciousPatterns);
            logger.info('URL mismatches:', urlMismatches);

            return {
                extractedUrls: allUrls,
                flaggedUrls,
                suspiciousPatterns,
                urlMismatches
            };
        } catch (error) {
            logger.error('Error analyzing email body:', error);
            return null;
        }
    }
}

export const urlAnalyzer = new UrlAnalyzer();