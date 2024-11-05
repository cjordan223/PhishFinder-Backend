// src/utils/urlUtils.js
import fetch from 'node-fetch';

//helper functions to extract the urls from the email content

export function extractUrlsFromHtml(htmlContent) {
  const hrefRegex = /href=["'](https?:\/\/[^"']+)["']/g;
  const hrefMatches = [...htmlContent.matchAll(hrefRegex)].map(match => match[1]);
  
  const anchorRegex = />https?:\/\/[^<\s]+</g;
  const anchorMatches = [...htmlContent.matchAll(anchorRegex)]
    .map(match => match[0].slice(1, -1)); // Remove > and <
  
  const mismatches = detectUrlMismatches(htmlContent);
  
  const allUrls = [...new Set([...hrefMatches, ...anchorMatches])]
    .map(url => {
      return {
        url: url
          .trim()
          .replace(/['"<>]/g, '')
          .split(/[|\s]/)[0]
          .replace(/&amp;/g, '&')
          .replace(/\/$/, ''),
        suspicious: false
      };
    })
    .filter(urlObj => {
      try {
        new URL(urlObj.url);
        return true;
      } catch {
        return false;
      }
    });

  // Combine regular URLs and mismatches
  return [...allUrls, ...mismatches];
}

export function extractUrlsFromText(text) {
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

export async function checkUrlsWithSafeBrowsing(urls, safeBrowsingUrl) {
  if (!urls || urls.length === 0) return [];

  const uniqueUrls = [...new Set(urls)];

  const requestBody = {
    client: {
      clientId: "phishfinder-extension",
      clientVersion: "1.0",
    },
    threatInfo: {
      // here we define the types of threats we want to check for using the safe browsing api fields
      threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: uniqueUrls.map(url => ({ url })),
    },
  };

  try {
    const response = await fetch(safeBrowsingUrl, {
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

// Add new function to detect URL mismatches
function detectUrlMismatches(htmlContent) {
    const mismatches = [];
    
    // Look for anchor tags with both href and text content
    const anchorRegex = /<a[^>]+href=["']([^"']+)["'][^>]*>([^<]+)<\/a>/g;
    let match;
    
    while ((match = anchorRegex.exec(htmlContent)) !== null) {
        const href = match[1].trim();
        const displayText = match[2].trim();
        
        // Check if displayText looks like a URL
        const urlPattern = /^(https?:\/\/)?[\w\-.]+(\.[\w\-.]+)+[^\s]*$/i;
        if (urlPattern.test(displayText)) {
            // Compare normalized versions of both URLs
            const normalizedHref = normalizeUrl(href);
            const normalizedDisplay = normalizeUrl(displayText);
            
            if (normalizedHref !== normalizedDisplay) {
                mismatches.push({
                    displayedUrl: displayText,
                    actualUrl: href,
                    suspicious: true
                });
            }
        }
    }
    
    return mismatches;
}

function normalizeUrl(url) {
    try {
        // Add protocol if missing
        if (!url.startsWith('http')) {
            url = 'https://' + url;
        }
        const parsed = new URL(url);
        return parsed.hostname.toLowerCase();
    } catch {
        return url.toLowerCase();
    }
}