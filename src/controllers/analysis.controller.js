import { saveEmailAnalysis } from '../config/db.js';
import { extractUrlsFromHtml, extractUrlsFromText, checkUrlsWithSafeBrowsing } from '../utils/urlUtils.js';
import { getEmailAuthenticationDetails } from '../services/dns.service.js';
import { analyzeSuspiciousPatterns, checkUrlMismatches, extractSpfStatus, extractDmarcPolicy, determineCategory, extractCipherInfo, determineIfResponseRequired} from '../services/analysis.service.js';
import { cleanEmailBody, extractReadableText, getTextMetrics } from '../utils/textCleaner.js';
import { extractOrganization, cleanOrgName } from '../utils/emailParser.js';

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

    console.log('Analyzing email:', { id, sender, subject });

    try {
        if (typeof body !== 'string') {
            throw new Error('Invalid input: email body must be a string');
        }

        // New: Clean and prepare the body text
        const cleanedBody = cleanEmailBody(body);
        const readableText = extractReadableText(cleanedBody);

        console.log('Cleaned body:', cleanedBody);
        console.log('Readable text:', readableText);


        // Add metrics about the cleaning process
        const textMetrics = getTextMetrics(body, cleanedBody, readableText);
        
        console.log('Text cleaning metrics:', textMetrics);

        // 1. Extract URLs from both HTML and text content
        const htmlUrls = extractUrlsFromHtml(cleanedBody);
        const textUrls = extractUrlsFromText(readableText);
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
        const suspiciousPatterns = analyzeSuspiciousPatterns(readableText, subject);
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
            timestamp: new Date(timestamp),
            sender: {
                address: sender.address,
                displayName: sender.displayName,
                domain: sender.domain,
                replyTo: headers.find(h => h.name === 'Reply-To')?.value || null,
                organization: extractOrganization(sender.domain, cleanedBody),
                organizationNormalized: cleanOrgName(extractOrganization(sender.domain, cleanedBody))
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
            behavioral: {
                emailClient: headers.find(h => h.name === 'X-Mailer')?.value || 'unknown',
                labels: labels || [],
                category: determineCategory(labels, subject, cleanedBody),
                importance: labels.includes('IMPORTANT') ? 'high' : 'normal',
                responseRequired: determineIfResponseRequired(cleanedBody)
            },
            metadata: {
                messageId: headers.find(h => h.name === 'Message-ID')?.value,
                internalDate,
                sizeEstimate
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

