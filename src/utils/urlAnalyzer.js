import { PhishDetector } from 'phish-detector';
import { LinkChecker } from 'linkinator';
import logger from '../config/logger.js';
import UrlUtils from './urlUtils.js';

class UrlAnalyzer {
    constructor() {
        this.phishDetector = new PhishDetector();
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

            // Check for common phishing patterns
            const phishScore = await this.phishDetector.analyze(href);
            if (phishScore > 0.7) {
                analysis.suspicious = true;
                analysis.reasons.push('phishing_indicators');
            }

            // Check with Safe Browsing API
            const safeBrowsingResults = await UrlUtils.checkUrlsWithSafeBrowsing([href]);
            if (safeBrowsingResults.length > 0) {
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
}

export const urlAnalyzer = new UrlAnalyzer();