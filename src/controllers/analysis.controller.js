// src/controllers/analysis.controller.js
import { saveEmailAnalysis } from '../services/emailAnalysis.service.js';
import { extractUrlsFromHtml, extractUrlsFromText, checkUrlsWithSafeBrowsing, detectUrlMismatches } from '../utils/urlUtils.js';
import { getEmailAuthenticationDetails } from '../services/dns.service.js';
import { analyzeSuspiciousPatterns, extractSpfStatus, extractDmarcPolicy, determineCategory, extractCipherInfo, determineIfResponseRequired } from '../services/analysis.service.js';
import { cleanEmailBody, extractReadableText, getTextMetrics } from '../utils/textCleaner.js';
import { extractOrganization, cleanOrgName } from '../utils/emailParser.js';
import logger from '../config/logger.js';
import { extractDisplayName, extractDomain } from '../utils/receiverUtils.js';
import { connectDB } from '../config/db.js';

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
        // Input validation
        if (typeof body !== 'string') {
            throw new Error('Invalid input: email body must be a string');
        }

        // Log raw email body for debugging
        logger.debug(`Raw email body: ${body}`);

        // First get URL mismatches from raw body to preserve HTML structure
        const urlMismatches = detectUrlMismatches(body);
        logger.info(`URL mismatches: ${JSON.stringify(urlMismatches)}`);

        // Clean and prepare the body text for other analysis
        const { preservedHtml, cleanedText } = cleanEmailBody(body);
        const readableText = extractReadableText(preservedHtml);

        logger.info(`Cleaned body: ${cleanedText}`);
        logger.info(`Readable text: ${readableText}`);

        // Get text cleaning metrics
        const textMetrics = getTextMetrics(body, cleanedText, readableText);
        logger.info(`Text cleaning metrics: ${JSON.stringify(textMetrics)}`);

        // 1. URL Analysis
        // Extract URLs from both preserved HTML and cleaned text
        const htmlUrls = extractUrlsFromHtml(preservedHtml);
        const textUrls = extractUrlsFromText(readableText);
        const allUrls = [...new Set([...htmlUrls, ...textUrls])];
        logger.info(`Extracted URLs: ${JSON.stringify(allUrls)}`);

        // 2. Safe Browsing Check
        const safeBrowsingApiKey = process.env.SAFE_BROWSING_API_KEY;
        if (!safeBrowsingApiKey) {
            throw new Error('SAFE_BROWSING_API_KEY is not configured');
        }
        
        const flaggedUrls = await checkUrlsWithSafeBrowsing(allUrls.map(urlObj => urlObj.url));
        logger.info(`Flagged URLs: ${JSON.stringify(flaggedUrls)}`);

        // 3. Pattern Analysis
        const suspiciousPatterns = analyzeSuspiciousPatterns(readableText, subject);
        logger.info(`Suspicious patterns: ${JSON.stringify(suspiciousPatterns)}`);

        // 4. DNS Authentication
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

        // 5. Analysis Results
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
                        url: url.url,
                        isSuspicious: url.suspicious || flaggedUrls.some(f => f.url === url.url),
                        threatType: flaggedUrls.find(f => f.url === url.url)?.threatType || null,
                        mismatch: urlMismatches.find(m => m.actualUrl === url.url)
                    })),
                    safeBrowsingResult: flaggedUrls,
                    urlMismatches: urlMismatches
                }
            },
            behavioral: {
                category: determineCategory(labels, subject, cleanedText),
                requiresResponse: determineIfResponseRequired(subject, readableText, labels),
                priority: labels.includes('IMPORTANT') ? 'high' : 'normal',
                isThread: labels.includes('SENT') || headers.some(h => h.name === 'In-Reply-To'),
                threadId: headers.find(h => h.name === 'Thread-Index')?.value || null
            }
        };

        // 6. Prepare Email Data
        const emailData = {
            id,
            timestamp: new Date(timestamp),
            sender: {
                address: sender.address,
                displayName: sender.displayName,
                domain: sender.domain,
                replyTo: headers.find(h => h.name === 'Reply-To')?.value || null,
                organization: extractOrganization(sender.domain, cleanedText),
                organizationNormalized: cleanOrgName(extractOrganization(sender.domain, cleanedText))
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
                    urlMismatches: urlMismatches
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
                    hasUrlMismatches: urlMismatches.length > 0
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

        // 7. Save Email and Process Profiles
        const resultId = await saveEmailAnalysis(emailData, true);
        logger.info(`Saved to database with ID: ${resultId}`);

        // 8. Send Response
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

export const analyzeEmailOnly = async (req, res) => {
    const { id } = req.params;
    const { 
        sender, 
        subject, 
        body, 
        htmlBody,
        timestamp,
        headers,
        parts,
        labels,
        historyId,
        internalDate,
        sizeEstimate,
        rawPayload
    } = req.body;

    logger.info(`Analyzing email ${id} without persistence:`, {
        sender,
        subject,
        bodyLength: body?.length,
        timestamp
    });

    try {
        // Input validation
        if (!body && !htmlBody) {
            throw new Error('Invalid input: email must have either body or htmlBody');
        }

        // Use htmlBody if available, otherwise use regular body
        const emailBody = htmlBody || body;

        // First get URL mismatches from raw body to preserve HTML structure
        const urlMismatches = detectUrlMismatches(emailBody);
        logger.info(`URL mismatches found:`, urlMismatches);

        // Clean and prepare the body text for other analysis
        const { preservedHtml, cleanedText } = cleanEmailBody(emailBody);
        const readableText = extractReadableText(preservedHtml);

        // URL Analysis
        const htmlUrls = extractUrlsFromHtml(preservedHtml);
        const textUrls = extractUrlsFromText(readableText);
        const allUrls = [...new Set([...htmlUrls, ...textUrls])];
        logger.info(`Extracted URLs:`, allUrls);

        // Safe Browsing Check
        const safeBrowsingApiKey = process.env.SAFE_BROWSING_API_KEY;
        if (!safeBrowsingApiKey) {
            throw new Error('SAFE_BROWSING_API_KEY is not configured');
        }
        
        const flaggedUrls = await checkUrlsWithSafeBrowsing(allUrls.map(urlObj => urlObj.url));
        logger.info(`Flagged URLs:`, flaggedUrls);

        // Pattern Analysis
        const suspiciousPatterns = analyzeSuspiciousPatterns(readableText, subject);
        logger.info(`Suspicious patterns: ${JSON.stringify(suspiciousPatterns)}`);

        // DNS Authentication
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

        // Prepare Analysis Result
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
                        url: url.url,
                        isSuspicious: url.suspicious || flaggedUrls.some(f => f.url === url.url),
                        threatType: flaggedUrls.find(f => f.url === url.url)?.threatType || null,
                        mismatch: urlMismatches.find(m => m.actualUrl === url.url)
                    })),
                    safeBrowsingResult: flaggedUrls,
                    urlMismatches: urlMismatches
                }
            },
            behavioral: {
                category: determineCategory(labels, subject, cleanedText),
                requiresResponse: determineIfResponseRequired(subject, readableText, labels),
                priority: labels.includes('IMPORTANT') ? 'high' : 'normal',
                isThread: labels.includes('SENT') || headers.some(h => h.name === 'In-Reply-To'),
                threadId: headers.find(h => h.name === 'Thread-Index')?.value || null
            }
        };

        res.json({
            success: true,
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

export const getEmailAnalysis = async (req, res) => {
    const { id } = req.params;
    
    try {
        const db = await connectDB();
        const email = await db.collection('emails').findOne({ id });
        
        if (!email) {
            return res.status(404).json({ 
                success: false, 
                error: 'Email not found' 
            });
        }

        // Transform the stored email data into the analysis result format
        const analysisResult = {
            security: {
                authentication: {
                    spf: email.security.authentication.spf.record,
                    dkim: email.security.authentication.dkim.record,
                    dmarc: email.security.authentication.dmarc.record,
                    summary: `SPF: ${email.security.authentication.spf.status}, 
                             DKIM: ${email.security.authentication.dkim.status}, 
                             DMARC: ${email.security.authentication.dmarc.policy}`
                },
                analysis: {
                    isFlagged: email.security.flags.safebrowsingFlag || 
                              email.security.flags.hasSuspiciousPatterns || 
                              email.security.flags.hasUrlMismatches,
                    suspiciousKeywords: email.security.suspiciousPatterns || [],
                    linkRisks: email.content.metrics.extractedUrls.map(url => ({
                        url: url.url,
                        isSuspicious: url.suspicious,
                        threatType: null, // Add this if you store it
                        mismatch: email.content.metrics.urlMismatches.find(m => m.actualUrl === url.url)
                    })),
                    safeBrowsingResult: [], // Add this if you store it
                    urlMismatches: email.content.metrics.urlMismatches
                }
            },
            behavioral: {
                category: email.behavioral?.category || 'general',
                requiresResponse: email.behavioral?.requiresResponse || false,
                priority: email.behavioral?.priority || 'normal',
                isThread: email.behavioral?.isThread || false,
                threadId: email.behavioral?.threadId || null
            }
        };

        res.json({
            success: true,
            ...analysisResult
        });

    } catch (error) {
        logger.error(`Error retrieving email analysis: ${error.message}`);
        res.status(500).json({ 
            success: false, 
            error: 'Error retrieving email analysis',
            details: error.message 
        });
    }
};