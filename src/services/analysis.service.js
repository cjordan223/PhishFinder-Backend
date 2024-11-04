
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
            console.warn('Error parsing URL in mismatch check:', e);
        }
    }

    return mismatches;
}

// Endpoint to analyze content for URLs and check them with Safe Browsing API
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

// Endpoint to analyze content using AI
// currently unused



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