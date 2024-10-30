// Import necessary modules
import express from 'express';
import cors from 'cors';
import fetch from 'node-fetch';
import dotenv from 'dotenv';
import { connectDB, saveEmailAnalysis } from './src/config/db.js'; // Import the connectDB function

dotenv.config(); // Load environment variables from .env file

const app = express();
const PORT = process.env.PORT || 8080; // Set the port for the server
const SAFE_BROWSING_API_KEY = process.env.SAFE_BROWSING_API_KEY; // Safe Browsing API key
const SAFE_BROWSING_URL = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${SAFE_BROWSING_API_KEY}`; // Safe Browsing API URL

// Allowed origins for CORS
const allowedOrigins = [
  'http://localhost:8080',
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
app.use(express.json()); // Middleware to parse JSON bodies

// Function to extract URLs from HTML content
function extractUrlsFromHtml(htmlContent) {
  const hrefRegex = /href=["'](https?:\/\/[^"']+)["']/g;
  const hrefMatches = [...htmlContent.matchAll(hrefRegex)].map(match => match[1]);
  
  const anchorRegex = />https?:\/\/[^<\s]+</g;
  const anchorMatches = [...htmlContent.matchAll(anchorRegex)]
    .map(match => match[0].slice(1, -1)); // Remove > and <
  
  const allUrls = [...new Set([...hrefMatches, ...anchorMatches])]
    .map(url => {
      return url
        .trim()
        .replace(/['"<>]/g, '') // Remove quotes and angle brackets
        .split(/[|\s]/)[0] // Take only the first part if URL contains spaces or pipes
        .replace(/&amp;/g, '&') // Replace HTML entities
        .replace(/\/$/, ''); // Remove trailing slash
    })
    .filter(url => {
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

// Function to extract URLs from plain text
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

// Function to check URLs with Safe Browsing API
async function checkUrlsWithSafeBrowsing(urls) {
  if (!urls || urls.length === 0) return [];

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
    const flaggedUrls = data.matches ? data.matches.map(match => ({ url: match.threat.url, threatType: match.threatType })) : [];
    return [...new Set(flaggedUrls.map(JSON.stringify))].map(JSON.parse); // Deduplicate flagged URLs
  } catch (error) {
    console.error("Safe Browsing API error:", error);
    return [];
  }
}

// Route to save email analysis to the database
app.post('/api/saveEmailAnalysis', async (req, res) => {
  const { id, sender, subject, body, extractedUrls, timestamp, safebrowsingFlag } = req.body;

  const emailData = {
    id,
    sender,
    subject,
    body,
    extractedUrls,
    timestamp: new Date(timestamp),
    safebrowsingFlag,
  };

  try {
    const resultId = await saveEmailAnalysis(emailData);
    res.json({ success: true, id: resultId });
  } catch (error) {
    console.error('Error saving email analysis:', error);
    res.status(500).json({ success: false, error: 'Error saving email analysis.' });
  }
});

// Route to analyze content for URLs and check them with Safe Browsing API
app.post('/api/analyze', async (req, res) => {
  try {
    let { text, isHtml } = req.body;

    if (!text) {
      return res.status(400).json({ error: 'No content provided.' });
    }

    const urls = isHtml ? extractUrlsFromHtml(text) : extractUrlsFromText(text);
    console.log('Extracted URLs:', urls);

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

// Route to analyze content using an AI content detector API
app.post('/api/ai-analyze', async (req, res) => {
  let { text } = req.body;

  let wordsArray = text.trim().split(/\s+/); // Split by spaces
  const wordCount = wordsArray.length;

  console.log(`Received text with word count: ${wordCount}`);

  if (wordCount > 298) {
    console.log('Text exceeds 298 words. Trimming to 298 words.');
    wordsArray = wordsArray.slice(0, 298); // Keep the first 298 words
    text = wordsArray.join(' '); // Rebuild the text from the trimmed array
  }

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







// (ALMOST) EVERYTHING BELOW IS RELATED TO THE METRICS. PROBABLY NEEDS ITS OWN FILE / STRUCTURE BUT HAVENT'T HAD TIME

// Route to fetch metrics for the dashboard
app.get('/api/metrics/:timeRange', async (req, res) => {
  try {
    const { timeRange } = req.params;
    const db = await connectDB();
    const emailsCollection = db.collection('emails');

    const endDate = new Date();
    const startDate = new Date();
    switch (timeRange) {
      case '7d':
        startDate.setDate(endDate.getDate() - 7);
        break;
      case '30d':
        startDate.setDate(endDate.getDate() - 30);
        break;
      case '90d':
        startDate.setDate(endDate.getDate() - 90);
        break;
      default:
        startDate.setDate(endDate.getDate() - 7);
    }

    const currentPeriodMetrics = await emailsCollection.aggregate([
      {
        $match: {
          timestamp: { $gte: startDate, $lte: endDate }
        }
      },
      {
        $group: {
          _id: null,
          totalEmails: { $sum: 1 },
          flaggedEmails: {
            $sum: { $cond: [{ $eq: ["$safebrowsingFlag", "yes"] }, 1, 0] }
          },
          suspiciousUrls: { $sum: { $size: "$extractedUrls" } }
        }
      }
    ]).toArray();

    const previousStartDate = new Date(startDate);
    previousStartDate.setDate(previousStartDate.getDate() - timeRange);
    
    const previousPeriodMetrics = await emailsCollection.aggregate([
      {
        $match: {
          timestamp: { $gte: previousStartDate, $lt: startDate }
        }
      },
      {
        $group: {
          _id: null,
          totalEmails: { $sum: 1 },
          suspiciousUrls: { $sum: { $size: "$extractedUrls" } }
        }
      }
    ]).toArray();

    const dailyStats = await emailsCollection.aggregate([
      {
        $match: {
          timestamp: { $gte: startDate, $lte: endDate }
        }
      },
      {
        $group: {
          _id: { $dateToString: { format: "%Y-%m-%d", date: "$timestamp" } },
          totalEmails: { $sum: 1 },
          flaggedEmails: {
            $sum: { $cond: [{ $eq: ["$safebrowsingFlag", "yes"] }, 1, 0] }
          }
        }
      },
      {
        $sort: { "_id": 1 }
      },
      {
        $project: {
          date: "$_id",
          totalEmails: 1,
          flaggedEmails: 1,
          _id: 0
        }
      }
    ]).toArray();

    const averageRiskScore = 85; // Placeholder 

    res.json({
      totalEmails: currentPeriodMetrics[0]?.totalEmails || 0,
      previousTotalEmails: previousPeriodMetrics[0]?.totalEmails || 0,
      flaggedEmails: currentPeriodMetrics[0]?.flaggedEmails || 0,
      averageRiskScore,
      suspiciousUrls: currentPeriodMetrics[0]?.suspiciousUrls || 0,
      previousSuspiciousUrls: previousPeriodMetrics[0]?.suspiciousUrls || 0,
      dailyStats
    });

  } catch (error) {
    console.error('Error fetching metrics:', error);
    res.status(500).json({ error: 'Error fetching metrics' });
  }
});

// Connect to MongoDB before starting the server
connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`Backend server running on port ${PORT}`);
  });
}).catch((error) => {
  console.error("Failed to start server:", error);
  process.exit(1); // Exit the process if unable to connect to MongoDB
});