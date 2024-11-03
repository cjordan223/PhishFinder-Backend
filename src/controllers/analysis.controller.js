import { saveEmailAnalysis } from '../config/db.js';
import { extractUrlsFromHtml, extractUrlsFromText, checkUrlsWithSafeBrowsing } from '../utils/urlUtils.js';
import { getEmailAuthenticationDetails } from '../services/dns.service.js';

// New comprehensive email analysis endpoint
export const analyzeEmail = async (req, res) => {
    const { id, sender, subject, body, timestamp, rawPayload } = req.body;
    console.log('Analyzing email:', { id, sender, subject });

    try {
        // 1. Extract URLs from both HTML and text content
        const htmlUrls = extractUrlsFromHtml(body);
        const textUrls = extractUrlsFromText(body);
        const allUrls = [...new Set([...htmlUrls, ...textUrls])];
        console.log('Extracted URLs:', allUrls);

        // 2. Perform Safe Browsing check
        const safeBrowsingUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${process.env.SAFE_BROWSING_API_KEY}`;
        const flaggedUrls = await checkUrlsWithSafeBrowsing(allUrls, safeBrowsingUrl);
        console.log('Flagged URLs:', flaggedUrls);

        // 3. Check for suspicious patterns
        const suspiciousPatterns = analyzeSuspiciousPatterns(body, subject);
        console.log('Suspicious patterns:', suspiciousPatterns);

        // 4. Check for URL/link name mismatches
        const urlMismatches = checkUrlMismatches(body);
        console.log('URL mismatches:', urlMismatches);

        // 5. DNS authentication checks using your existing service
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

// Helper function to analyze suspicious patterns
function analyzeSuspiciousPatterns(body, subject) {
    const suspiciousPatterns = [];
    const patterns = [
        {
            pattern: /urgent|immediate action|account.*suspend|verify.*account/gi,
            type: 'Urgency/Threat',
        },
        {
            pattern: /password|credential|login|sign in/gi,
            type: 'Credential Harvesting',
        },
        {
            pattern: /\$|money|payment|transfer|bank|account/gi,
            type: 'Financial',
        },
        {
            pattern: /won|winner|lottery|prize|reward/gi,
            type: 'Prize/Reward',
        }
    ];

    // Check subject and body
    [
        { text: subject, location: 'subject' },
        { text: body, location: 'body' }
    ].forEach(({ text, location }) => {
        if (!text) return;
        
        patterns.forEach(({ pattern, type }) => {
            const matches = text.match(pattern);
            if (matches) {
                suspiciousPatterns.push({
                    type,
                    location,
                    matches: [...new Set(matches)] // Deduplicate matches
                });
            }
        });
    });

    return suspiciousPatterns;
}

// Helper function to check for URL/link name mismatches
function checkUrlMismatches(body) {
    const mismatches = [];
    const linkPattern = /<a[^>]+href=["']([^"']+)["'][^>]*>([^<]+)<\/a>/gi;
    let match;

    while ((match = linkPattern.exec(body)) !== null) {
        const [, href, text] = match;
        try {
            const hrefDomain = new URL(href).hostname;
            // Check if text contains a URL
            const urlInText = text.match(/https?:\/\/[^\s<]+/);
            const textDomain = urlInText ? new URL(urlInText[0]).hostname : text;

            if (hrefDomain !== textDomain && !text.includes(hrefDomain)) {
                mismatches.push({
                    url: href,
                    displayText: text,
                    actualDomain: hrefDomain,
                    displayDomain: textDomain
                });
            }
        } catch (e) {
            console.warn('Error parsing URL in mismatch check:', e);
        }
    }

    return mismatches;
}

export const saveAnalysis = async (req, res) => {
  const { id, sender, subject, body, extractedUrls, timestamp, safebrowsingFlag, spf, dmarc, dkim } = req.body;

  const emailData = {
    id,
    sender,
    subject,
    body,
    extractedUrls,
    timestamp: new Date(timestamp),
    safebrowsingFlag,
    spf,
    dmarc,
    dkim,
  };

  try {
    const resultId = await saveEmailAnalysis(emailData);
    res.json({ success: true, id: resultId });
  } catch (error) {
    console.error('Error saving email analysis:', error);
    res.status(500).json({ success: false, error: 'Error saving email analysis.' });
  }
};

export async function analyzeContent(req, res) {
  const { text } = req.body;

  // Debugging: Log the received text
  console.log('Received text for analysis:', text);

  // Check if text is a string
  if (typeof text !== 'string') {
    console.error('Expected a string for text, but received:', typeof text);
    return res.status(400).json({ error: 'Invalid input: text must be a string' });
  }

  const urls = extractUrlsFromText(text);
  const safeBrowsingApiKey = process.env.SAFE_BROWSING_API_KEY;

  // Construct the Safe Browsing API URL
  const safeBrowsingUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${safeBrowsingApiKey}`;

  // Debugging: Log the constructed URL
  console.log('Constructed SAFE_BROWSING_API_URL:', safeBrowsingUrl);

  if (!safeBrowsingApiKey) {
    console.error('SAFE_BROWSING_API_KEY is not defined');
    return res.status(500).json({ error: 'Server configuration error' });
  }

  try {
    const flaggedUrls = await checkUrlsWithSafeBrowsing(urls, safeBrowsingUrl);
    res.json({ flaggedUrls });
  } catch (error) {
    console.error('Error analyzing content:', error);
    res.status(500).json({ error: 'Error analyzing content' });
  }
}

export const analyzeAIContent = async (req, res) => {
  let { text } = req.body;
  let wordsArray = text.trim().split(/\s+/);
  const wordCount = wordsArray.length;

  // Debugging: Log the incoming request and API token
  console.log('Received text for AI analysis:', text);
  console.log('Using API_TOKEN:', process.env.API_TOKEN);
  
  if (wordCount > 298) {
    wordsArray = wordsArray.slice(0, 298);
    text = wordsArray.join(' ');
  }

  if (wordsArray.length < 10) {
    return res.status(400).json({ error: 'Text must be between 10 and 298 words.' });
  }

  try {
    const response = await fetch('https://www.freedetector.ai/api/content_detector/', {
      method: 'POST',
      headers: {
        'Authorization': process.env.API_TOKEN,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ text }),
    });
    
    const result = await response.json();

    if (result.success) {
      res.json({ score: result.score });
    } else {
      console.error('API returned error:', result);
      res.status(500).json({ error: result.message || 'API error occurred.' });
    }
  } catch (error) {
    console.error('Error making request to AI Detector API:', error);
    res.status(500).json({ error: 'Error analyzing content.' });
  }
};