import { saveEmailAnalysis } from '../services/emailAnalysis.service.js';
import { extractUrlsFromHtml, extractUrlsFromText, checkUrlsWithSafeBrowsing } from '../utils/urlUtils.js';
import { getEmailAuthenticationDetails } from '../services/dns.service.js';
import { analyzeSuspiciousPatterns, checkUrlMismatches, extractSpfStatus, extractDmarcPolicy, determineCategory, extractCipherInfo, determineIfResponseRequired } from '../services/analysis.service.js';
import { cleanEmailBody, extractReadableText, getTextMetrics } from '../utils/textCleaner.js';
import { extractOrganization, cleanOrgName } from '../utils/emailParser.js';
import logger from '../config/logger.js';
import { extractDisplayName, extractDomain } from '../utils/receiverUtils.js';

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
        rawPayload
    } = req.body;

    logger.info(`Analyzing email: ${JSON.stringify({ id, sender, subject })}`);

    try {
        if (typeof body !== 'string') {
            throw new Error('Invalid input: email body must be a string');
        }

        // Clean and prepare the body text
        const cleanedBody = cleanEmailBody(body);
        const readableText = extractReadableText(cleanedBody);

        logger.info(`Cleaned body: ${cleanedBody}`);
        logger.info(`Readable text: ${readableText}`);

        // Add metrics about the cleaning process
        const textMetrics = getTextMetrics(body, cleanedBody, readableText);
        logger.info(`Text cleaning metrics: ${JSON.stringify(textMetrics)}`);

        // 1. Extract URLs from both HTML and text content
        const htmlUrls = extractUrlsFromHtml(cleanedBody);
        const textUrls = extractUrlsFromText(readableText);
        const allUrls = [...new Set([...htmlUrls, ...textUrls])];
        logger.info(`Extracted URLs: ${JSON.stringify(allUrls)}`);

        // 2. SafeBrowsing API setup and check
        const safeBrowsingApiKey = process.env.SAFE_BROWSING_API_KEY;
        if (!safeBrowsingApiKey) {
            throw new Error('SAFE_BROWSING_API_KEY is not configured');
        }
        
        const safeBrowsingUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${safeBrowsingApiKey}`;
        const flaggedUrls = await checkUrlsWithSafeBrowsing(allUrls, safeBrowsingUrl);
        logger.info(`Flagged URLs: ${JSON.stringify(flaggedUrls)}`);

        // 3. Check for suspicious patterns
        const suspiciousPatterns = analyzeSuspiciousPatterns(readableText, subject);
        logger.info(`Suspicious patterns: ${JSON.stringify(suspiciousPatterns)}`);

        // 4. Check for URL/link name mismatches
        const urlMismatches = checkUrlMismatches(body);
        logger.info(`URL mismatches: ${JSON.stringify(urlMismatches)}`);

        // 5. DNS authentication checks
        let dnsRecords = {
            spf: null,
            dkim: null,
            dmarc: null,
            summary: 'DNS checks not performed'
        };

        if (sender?.domain) {
            dnsRecords = await getEmailAuthenticationDetails(sender.domain);
            logger.info(`DNS records: ${JSON.stringify(dnsRecords)}`);
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
            },
            behavioral: {
                category: determineCategory(labels, subject, cleanedBody),
                requiresResponse: determineIfResponseRequired(subject, readableText, labels),
                priority: labels.includes('IMPORTANT') ? 'high' : 'normal',
                isThread: labels.includes('SENT') || headers.some(h => h.name === 'In-Reply-To'),
                threadId: headers.find(h => h.name === 'Thread-Index')?.value || null
            }
        };

        // 7. Save to database with immediate profile processing
        const emailData = {
            id,
            timestamp: new Date(timestamp),
            sender: {
                address: sender.address,
                displayName: sender.displayName,
                domain: sender.domain,
                replyTo: headers.find(h => h.name === 'Reply-To')?.value || null,
                organization: extractOrganization(sender.domain, cleanedBody),
                organizationNormalized: cleanOrgName(extractOrganization(sender.domain, cleanedBody))
            },
            receiver: {
                address: headers.find(h => h.name === 'To')?.value || null,
                displayName: extractDisplayName(headers.find(h => h.name === 'To')?.value),
                domain: extractDomain(headers.find(h => h.name === 'To')?.value),
                cc: headers.find(h => h.name === 'Cc')?.value || null,
                bcc: headers.find(h => h.name === 'Bcc')?.value || null
            },
            subject,
            content: {
                cleanedBody: readableText,
                metrics: {
                    ...textMetrics,
                    contentType: headers.find(h => h.name === 'Content-Type')?.value,
                    hasHtml: headers.some(h => h.name === 'Content-Type' && h.value.includes('html')),
                    extractedUrls: allUrls,
                    urlMismatches: allUrls.filter(u => u.suspicious)
                }
            },
            security: {
                authentication: {
                    spf: {
                        record: dnsRecords.spf,
                        status: extractSpfStatus(dnsRecords.spf)
                    },
                    dkim: {
                        record: dnsRecords.dkim,
                        status: dnsRecords.dkim === 'No DKIM record found' ? 'missing' : 'present'
                    },
                    dmarc: {
                        record: dnsRecords.dmarc,
                        policy: extractDmarcPolicy(dnsRecords.dmarc)
                    }
                },
                flags: {
                    safebrowsingFlag: flaggedUrls.length > 0,
                    hasExternalUrls: allUrls.length > 0,
                    hasMultipleRecipients: headers.some(h => h.name === 'To' && h.value.includes(',')),
                    hasSuspiciousPatterns: suspiciousPatterns.length > 0,
                    hasUrlMismatches: allUrls.some(u => u.suspicious)
                },
                transportSecurity: {
                    tls: headers.some(h => h.name === 'Received' && h.value.includes('TLS')),
                    cipher: extractCipherInfo(headers)
                }
            },
            metadata: {
                historyId,
                internalDate: new Date(parseInt(internalDate)),
                labels,
                sizeEstimate,
                parts: parts?.map(part => ({
                    mimeType: part.mimeType,
                    filename: part.filename,
                    headers: part.headers
                })) || []
            },
            senderProfileProcessed: false,
            languageProfileProcessed: false
        };

        // Save email and process profiles immediately
        const resultId = await saveEmailAnalysis(emailData, true);
        logger.info(`Saved to database with ID: ${resultId}`);

        // 8. Send response
        res.json({
            success: true,
            id: resultId,
            ...analysisResult
        });

    } catch (error) {
        logger.error(`Error analyzing email: ${error.message}`);
        res.status(500).json({ 
            success: false, 
            error: 'Error analyzing email',
            details: error.message 
        });
    }
};