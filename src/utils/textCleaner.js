import sanitizeHtml from 'sanitize-html';
import * as cheerio from 'cheerio';
import logger from '../config/logger.js';

export const cleanEmailBody = (body) => {
    try {
        // First pass: Remove HTML and get readable text
        let cleaned = sanitizeHtml(body, {
            allowedTags: [],
            allowedAttributes: {},
            textFilter: (text) => text.replace(/\s+/g, ' ').trim()
        });

        // Remove common email signatures and formatting
        cleaned = cleaned
            .replace(/(\r\n|\n|\r)/gm, '\n')
            .replace(/\n\s*\n\s*\n/g, '\n\n')
            .replace(/\s+/g, ' ')
            .split(/^--\s*$/m)[0] // Remove signature
            .split(/^Sent from/m)[0]
            .trim();

        return cleaned;
    } catch (err) {
        logger.error('Error cleaning email body:', err);
        return body;
    }
};

export const extractReadableText = (html) => {
    try {
        const $ = cheerio.load(html);
        $('style, script, link, meta, img').remove();
        return $('body').text().replace(/\s+/g, ' ').trim();
    } catch (err) {
        logger.error('Error extracting readable text:', err);
        return html;
    }
};

export const getTextMetrics = (original, cleaned) => {
    return {
        originalLength: original.length,
        cleanedLength: cleaned.length,
        wordCount: cleaned.split(/\s+/).length,
        sentences: cleaned.split(/[.!?]+/g).length
    };
};