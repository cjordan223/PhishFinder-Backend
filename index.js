import express from 'express';
import cors from 'cors';
import fetch from 'node-fetch';
import dotenv from 'dotenv';

dotenv.config(); // Load environment variables

const app = express();
const PORT = process.env.PORT || 3001;
const SAFE_BROWSING_API_KEY = process.env.SAFE_BROWSING_API_KEY;
const SAFE_BROWSING_URL = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${SAFE_BROWSING_API_KEY}`;

// Allowed origins for CORS
const allowedOrigins = [
  'http://localhost:3000',
  'chrome-extension://ogajmmpomfocfpjhalbfjhjeikidgkef',
];

// CORS configuration
const corsOptions = {
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: 'GET,POST',
  allowedHeaders: 'Content-Type,Authorization',
};

app.use(cors(corsOptions)); // Apply the CORS middleware
app.use(express.json());

// Enhanced URL extraction from HTML content
function extractUrlsFromHtml(htmlContent) {
  // First try to extract URLs from href attributes
  const hrefRegex = /href=["'](https?:\/\/[^"']+)["']/g;
  const hrefMatches = [...htmlContent.matchAll(hrefRegex)].map(match => match[1]);
  
  // Then try to extract URLs from anchor text
  const anchorRegex = />https?:\/\/[^<\s]+</g;
  const anchorMatches = [...htmlContent.matchAll(anchorRegex)]
    .map(match => match[0].slice(1, -1)); // Remove > and <
  
  // Combine and clean up URLs
  const allUrls = [...new Set([...hrefMatches, ...anchorMatches])]
    .map(url => {
      // Clean up the URL
      return url
        .trim()
        .replace(/['"<>]/g, '') // Remove quotes and angle brackets
        .split(/[|\s]/)[0] // Take only the first part if URL contains spaces or pipes
        .replace(/&amp;/g, '&') // Replace HTML entities
        .replace(/\/$/, ''); // Remove trailing slash
    })
    .filter(url => {
      // Validate URL format
      try {
        new URL(url);
        return true;
      } catch {
        return false;
      }
    });

  console.log('Extracted URLs from HTML:', allUrls);
  return allUrls;
}

// Extract URLs from plain text
function extractUrlsFromText(text) {
  const urlRegex = /https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&\/=]*)/g;
  const matches = text.match(urlRegex) || [];
  
  const cleanedUrls = matches
    .map(url => {
      return url
        .trim()
        .replace(/['"]/g, '') // Remove quotes
        .split(/[|\s]/)[0] // Take only the first part if URL contains spaces or pipes
        .replace(/&amp;/g, '&') // Replace HTML entities
        .replace(/\/$/, ''); // Remove trailing slash
    })
    .filter(url => {
      // Validate URL format
      try {
        new URL(url);
        return true;
      } catch {
        return false;
      }
    });

  console.log('Extracted URLs from text:', cleanedUrls);
  return cleanedUrls;
}

// Safe Browsing API URL check with deduplication
async function checkUrlsWithSafeBrowsing(urls) {
  if (!urls || urls.length === 0) return [];

  // Remove duplicate URLs
  const uniqueUrls = [...new Set(urls)];

  const requestBody = {
    client: {
      clientId: "phishfinder-extension",
      clientVersion: "1.0",
    },
    threatInfo: {
      threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: uniqueUrls.map(url => ({ url })),
    },
  };

  try {
    const response = await fetch(SAFE_BROWSING_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(requestBody),
    });

    if (!response.ok) {
      console.error("Safe Browsing API error:", response.statusText);
      return [];
    }

    const data = await response.json();
    // Return unique flagged URLs only
    const flaggedUrls = data.matches ? data.matches.map(match => ({ url: match.threat.url, threatType: match.threatType })) : [];
    return [...new Set(flaggedUrls.map(JSON.stringify))].map(JSON.parse); // Deduplicate flagged URLs
  } catch (error) {
    console.error("Safe Browsing API error:", error);
    return [];
  }
}

app.post('/api/analyze', async (req, res) => {
  try {
    let { text, isHtml } = req.body;

    if (!text) {
      return res.status(400).json({ error: 'No content provided.' });
    }

    const urls = isHtml ? extractUrlsFromHtml(text) : extractUrlsFromText(text);
    console.log('Extracted URLs:', urls);

    // Check URLs with Safe Browsing API
    const flaggedUrls = await checkUrlsWithSafeBrowsing(urls);
    console.log('Flagged URLs:', flaggedUrls);

    const isSuspicious = flaggedUrls.length > 0;

    res.json({
      isSuspicious,
      flaggedUrls,
      analysis: {
        totalUrls: urls.length,
        suspiciousUrls: flaggedUrls.length,
      }
    });
  } catch (error) {
    console.error('Error analyzing content:', error);
    res.status(500).json({
      error: 'Error analyzing content.',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});


app.post('/api/ai-analyze', async (req, res) => {
  let { text } = req.body;

  // Trim the text to a maximum of 298 words to account for API discrepancies
  let wordsArray = text.trim().split(/\s+/); // Split by spaces
  const wordCount = wordsArray.length;

  console.log(`Received text with word count: ${wordCount}`);

  if (wordCount > 298) {
    console.log('Text exceeds 298 words. Trimming to 298 words.');
    wordsArray = wordsArray.slice(0, 298); // Keep the first 298 words
    text = wordsArray.join(' '); // Rebuild the text from the trimmed array
  }

  // Ensure the text has at least 10 words after trimming
  if (wordsArray.length < 10) {
    console.error('Text length validation failed: Less than 10 words.');
    return res.status(400).json({ error: 'Text must be between 10 and 298 words.' });
  }

  console.log('API Token:', process.env.API_TOKEN); // Log the token for debugging

  try {
    const response = await fetch('https://www.freedetector.ai/api/content_detector/', {
      method: 'POST',
      headers: {
        'Authorization': process.env.API_TOKEN, // Ensure the token is loaded
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ text }),
    });

    console.log('Status:', response.status); // Log the status code
    console.log('Response Headers:', response.headers); // Log the headers for debugging
    
    const result = await response.json();
    console.log('AI Detector API Response:', result);

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
});


// Start the server
app.listen(PORT, () => {
  console.log(`Backend server running on port ${PORT}`);
});
