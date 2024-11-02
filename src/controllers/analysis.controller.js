
// src/controllers/analysis.controller.js
import { saveEmailAnalysis } from '../config/db.js';
import { extractUrlsFromHtml, extractUrlsFromText, checkUrlsWithSafeBrowsing } from '../utils/urlUtils.js';

export const saveAnalysis = async (req, res) => {
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
};

export async function analyzeContent(req, res) {
  const { text } = req.body;
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