import logger from '../config/logger.js';

// Helper function to analyze suspicious patterns
export function analyzeSuspiciousPatterns(body, subject) {
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
export function checkUrlMismatches(body) {
    const mismatches = [];
    const linkPattern = /<a[^>]+href=["']([^"']+)["'][^>]*>([^<]+)<\/a>/gi;
    let match;

    while ((match = linkPattern.exec(body)) !== null) {
        const [, href, text] = match;
        try {
            const hrefDomain = new URL(href).hostname;
            // Check if text contains a URL
            const urlInText = RegExp(/https?:\/\/[^\s<]+/).exec(text);
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
            logger.warn('Error parsing URL in mismatch check:', e);
        }
    }

    return mismatches;
}

// Endpoint to analyze content for URLs and check them with Safe Browsing API
export async function analyzeContent(req, res) {
  const { text } = req.body;

  // Debugging: Log the received text
  logger.info('Received text for analysis:', text);

  // Check if text is a string
  if (typeof text !== 'string') {
    logger.error('Expected a string for text, but received:', typeof text);
    return res.status(400).json({ error: 'Invalid input: text must be a string' });
  }

  const urls = extractUrlsFromText(text);
  const safeBrowsingApiKey = process.env.SAFE_BROWSING_API_KEY;

  // Construct the Safe Browsing API URL
  const safeBrowsingUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${safeBrowsingApiKey}`;

  // Debugging: Log the constructed URL
  logger.info('Constructed SAFE_BROWSING_API_URL:', safeBrowsingUrl);

  if (!safeBrowsingApiKey) {
    logger.error('SAFE_BROWSING_API_KEY is not defined');
    return res.status(500).json({ error: 'Server configuration error' });
  }

  try {
    const flaggedUrls = await checkUrlsWithSafeBrowsing(urls, safeBrowsingUrl);
    res.json({ flaggedUrls });
  } catch (error) {
    logger.error('Error analyzing content:', error);
    res.status(500).json({ error: 'Error analyzing content' });
  }
}

// Endpoint to analyze content using AI
// currently unused
export const analyzeAIContent = async (req, res) => {
  let { text } = req.body;
  let wordsArray = text.trim().split(/\s+/);
  const wordCount = wordsArray.length;

  // Debugging: Log the incoming request and API token
  logger.info('Received text for AI analysis:', text);
  logger.info('Using API_TOKEN:', process.env.API_TOKEN);
  
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
      logger.error('API returned error:', result);
      res.status(500).json({ error: result.message || 'API error occurred.' });
    }
  } catch (error) {
    logger.error('Error making request to AI Detector API:', error);
    res.status(500).json({ error: 'Error analyzing content.' });
  }
};

// Helper functions to extract/determine various properties
export function extractSpfStatus(spf) {
  if (!spf) return 'missing';
  if (spf.includes('~all')) return 'softfail';
  if (spf.includes('-all')) return 'hardfail';
  if (spf.includes('+all')) return 'pass';
  return 'neutral';
}

export function extractDmarcPolicy(dmarc) {
  if (!dmarc) return 'none';
  if (dmarc.includes('p=reject')) return 'reject';
  if (dmarc.includes('p=quarantine')) return 'quarantine';
  if (dmarc.includes('p=none')) return 'none';
  return 'unknown';
}

export function determineCategory(labels, subject, body) {
  // Implement logic to categorize emails
  if (labels.includes('CATEGORY_UPDATES')) return 'update';
  if (labels.includes('CATEGORY_PROMOTIONS')) return 'promotion';
  if (labels.includes('CATEGORY_SOCIAL')) return 'social';
  // Add more categories based on content analysis
  return 'general';
}

export function extractCipherInfo(headers) {
  const received = headers.find(h => h.name === 'Received' && h.value.includes('cipher='));
  if (!received) return null;
  const match = received.value.match(/cipher=([^\s]+)/);
  return match ? match[1] : null;
}

export function determineIfResponseRequired(body) {
  const responseIndicators = [
      'please respond',
      'please reply',
      'let me know',
      'confirm receipt',
      'awaiting your response'
  ];
  return responseIndicators.some(indicator => 
      body.toLowerCase().includes(indicator.toLowerCase())
  );
}

// Add to src/services/analysis.service.js
export function calculateRiskScore(emailData) {
  let score = 0;
  
  // Authentication checks (0-30 points)
  const auth = emailData.security?.authentication;
  if (auth) {
      if (auth.spf?.status === 'fail') score += 10;
      if (auth.dkim?.status === 'fail') score += 10;
      if (auth.dmarc?.policy === 'none') score += 10;
  }

  // URL/Link analysis (0-30 points)
  if (emailData.security?.flags) {
      if (emailData.security.flags.safebrowsingFlag) score += 15;
      if (emailData.security.flags.hasUrlMismatches) score += 10;
      if (emailData.security.flags.hasExternalUrls) score += 5;
  }

  // Content analysis (0-40 points)
  const patterns = emailData.security?.analysis?.suspiciousKeywords || [];
  score += Math.min(patterns.length * 5, 20); // Cap at 20 points

  if (emailData.security?.flags?.hasMultipleRecipients) score += 10;
  if (emailData.behavioral?.requiresResponse) score += 10;

  return Math.min(score, 100); // Cap total score at 100
}