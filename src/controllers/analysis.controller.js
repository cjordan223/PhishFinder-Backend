import { saveEmailAnalysis } from '../config/db.js';
import { extractUrlsFromHtml, extractUrlsFromText, checkUrlsWithSafeBrowsing } from '../utils/urlUtils.js';
import { getEmailAuthenticationDetails } from '../services/dns.service.js';
import { analyzeSuspiciousPatterns, checkUrlMismatches} from '../services/analysis.service.js';


/// controllers/analysis.controller.js

export const analyzeEmail = async (req, res) => {
    const { 
        id, 
        sender, 
        subject, 
        body, 
        timestamp,
        headers,
        parts,
        labels,
        historyId,
        internalDate,
        sizeEstimate,
        security,
        rawPayload
    } = req.body;

    console.log('Analyzing email:', { id, sender, subject });

    try {
        if (typeof body !== 'string') {
            throw new Error('Invalid input: email body must be a string');
        }

        // 1. Extract URLs from both HTML and text content
        const htmlUrls = extractUrlsFromHtml(body);
        const textUrls = extractUrlsFromText(body);
        const allUrls = [...new Set([...htmlUrls, ...textUrls])];
        console.log('Extracted URLs:', allUrls);

        // 2. SafeBrowsing API setup and check
        const safeBrowsingApiKey = process.env.SAFE_BROWSING_API_KEY;
        if (!safeBrowsingApiKey) {
            throw new Error('SAFE_BROWSING_API_KEY is not configured');
        }
        
        const safeBrowsingUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${safeBrowsingApiKey}`;
        const flaggedUrls = await checkUrlsWithSafeBrowsing(allUrls, safeBrowsingUrl);
        console.log('Flagged URLs:', flaggedUrls);

        // 3. Check for suspicious patterns
        const suspiciousPatterns = analyzeSuspiciousPatterns(body, subject);
        console.log('Suspicious patterns:', suspiciousPatterns);

        // 4. Check for URL/link name mismatches
        const urlMismatches = checkUrlMismatches(body);
        console.log('URL mismatches:', urlMismatches);

        // 5. DNS authentication checks
        let dnsRecords = {
            spf: null,
            dkim: null,
            dmarc: null,
            summary: 'DNS checks not performed'
        };

        if (sender?.domain) {
            dnsRecords = await getEmailAuthenticationDetails(sender.domain);
            console.log('DNS records:', dnsRecords);
        }

        // 6. Compile analysis results
        const analysisResult = {
            security: {
                authentication: {
                    spf: dnsRecords.spf,
                    dkim: dnsRecords.dkim,
                    dmarc: dnsRecords.dmarc,
                    summary: dnsRecords.summary
                },
                analysis: {
                    isFlagged: flaggedUrls.length > 0 || suspiciousPatterns.length > 0 || urlMismatches.length > 0,
                    suspiciousKeywords: suspiciousPatterns,
                    linkRisks: allUrls.map(url => ({
                        url,
                        isSuspicious: flaggedUrls.some(f => f.url === url),
                        threatType: flaggedUrls.find(f => f.url === url)?.threatType || null,
                        mismatch: urlMismatches.find(m => m.url === url)
                    })),
                    safeBrowsingResult: flaggedUrls
                }
            }
        };

        // 7. Save to database
        const emailData = {
            id,
            sender,
            subject,
            body,
            extractedUrls: allUrls,
            timestamp: new Date(timestamp),
            safebrowsingFlag: flaggedUrls.length > 0,
            spf: dnsRecords.spf,
            dmarc: dnsRecords.dmarc,
            dkim: dnsRecords.dkim,
            metadata: {
                date: timestamp,
                labels: labels || [],
                headers: headers || [],
                parts: parts || [],
                historyId,
                internalDate,
                sizeEstimate,
                rawPayload
            }
        };

        const resultId = await saveEmailAnalysis(emailData);
        console.log('Saved to database with ID:', resultId);

        // 8. Send response
        res.json({
            success: true,
            id: resultId,
            ...analysisResult
        });

    } catch (error) {
        console.error('Error analyzing email:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Error analyzing email',
            details: error.message 
        });
    }
};