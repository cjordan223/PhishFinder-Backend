import logger from '../config/logger.js';

export class RiskScoreService {
    calculateRiskScore(emailData) {
        let score = 0;
        const reasons = [];
        
        // Authentication checks (0-30 points)
        score += this.calculateAuthenticationScore(emailData, reasons);
        
        // URL/Link analysis (0-30 points)
        score += this.calculateUrlScore(emailData, reasons);
        
        // Content analysis (0-40 points)
        score += this.calculateContentScore(emailData, reasons);
        
        return {
            score: Math.min(score, 100),
            reasons,
            riskLevel: this.getRiskLevel(score),
            timestamp: new Date()
        };
    }

    calculateAuthenticationScore(emailData, reasons) {
        let score = 0;
        const auth = emailData.security?.authentication;
        
        if (auth) {
            if (auth.spf?.status === 'fail') {
                score += 10;
                reasons.push('SPF authentication failed');
            }
            if (auth.dkim?.status === 'fail') {
                score += 10;
                reasons.push('DKIM authentication failed');
            }
            if (auth.dmarc?.policy === 'none') {
                score += 10;
                reasons.push('No DMARC policy');
            }
        }
        
        return score;
    }

    calculateUrlScore(emailData, reasons) {
        let score = 0;
        const flags = emailData.security?.flags;
        
        if (flags) {
            if (flags.safebrowsingFlag) {
                score += 15;
                reasons.push('Unsafe URLs detected');
            }
            if (flags.hasUrlMismatches) {
                score += 10;
                reasons.push('URL mismatches found');
            }
            if (flags.hasExternalUrls) {
                score += 5;
                reasons.push('External URLs present');
            }
        }
        
        return score;
    }

    calculateContentScore(emailData, reasons) {
        let score = 0;
        const patterns = emailData.security?.analysis?.suspiciousKeywords || [];
        
        if (patterns.length > 0) {
            score += Math.min(patterns.length * 5, 20);
            reasons.push(`${patterns.length} suspicious patterns detected`);
        }

        if (emailData.security?.flags?.hasMultipleRecipients) {
            score += 10;
            reasons.push('Multiple recipients');
        }
        if (emailData.behavioral?.requiresResponse) {
            score += 10;
            reasons.push('Response required');
        }
        
        return score;
    }

    getRiskLevel(score) {
        if (score < 30) return 'low';
        if (score < 60) return 'medium';
        return 'high';
    }
}

export const riskScoreService = new RiskScoreService();