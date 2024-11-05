import URLParse from 'url-parse';
import { PhishDetector } from 'phish-detector';
import { LinkChecker } from 'linkinator';

class UrlAnalyzer {
    constructor() {
        this.phishDetector = new PhishDetector();
        this.linkChecker = new LinkChecker();
    }

    async analyzeUrl(displayText, href) {
        try {
            const analysis = {
                displayUrl: this.parseUrl(displayText),
                actualUrl: this.parseUrl(href),
                suspicious: false,
                reasons: [],
                redirects: [],
                security: {
                    ssl: false,
                    certificate: null,
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

            // Check for redirects
            const redirectChain = await this.checkRedirects(href);
            if (redirectChain.length > 1) {
                analysis.redirects = redirectChain;
                analysis.reasons.push('multiple_redirects');
            }

            return analysis;

        } catch (error) {
            console.error('URL analysis error:', error);
            return null;
        }
    }

    parseUrl(urlString) {
        try {
            // Handle cases where protocol is missing
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
                domain: this.extractDomain(parsed.hostname)
            };
        } catch (error) {
            console.error('URL parsing error:', error);
            return null;
        }
    }

    isDomainMismatch(displayUrl, actualUrl) {
        if (!displayUrl || !actualUrl) return false;
        return displayUrl.domain !== actualUrl.domain;
    }

    extractDomain(hostname) {
        // Remove subdomains, keep main domain + TLD
        const parts = hostname.split('.');
        if (parts.length > 2) {
            return parts.slice(-2).join('.');
        }
        return hostname;
    }

    async checkRedirects(url) {
        const results = await this.linkChecker.check(url);
        return results.links
            .filter(link => link.status === 301 || link.status === 302)
            .map(link => link.url);
    }
}

// Export singleton instance
export const urlAnalyzer = new UrlAnalyzer(); 