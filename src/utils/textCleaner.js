// src/utils/textCleaner.js
import sanitizeHtml from 'sanitize-html';
import * as cheerio from 'cheerio';
import logger from '../config/logger.js';
export const cleanEmailBody = (body) => {
    try {
        // First pass: Preserve HTML structure for URL analysis
        let preservedHtml = body.replace(/(\r\n|\n|\r)/gm, '\n')
                               .replace(/\n\s*\n\s*\n/g, '\n\n')
                               .trim();

        // Second pass: Clean text for language analysis
        let cleanedText = sanitizeHtml(body, {
            allowedTags: [],
            allowedAttributes: {},
            textFilter: (text) => text.replace(/\s+/g, ' ').trim()
        })
        .replace(/(\r\n|\n|\r)/gm, '\n')
        .replace(/\n\s*\n\s*\n/g, '\n\n')
        .replace(/\s+/g, ' ')
        .split(/^--\s*$/m)[0]
        .split(/^Sent from/m)[0]
        .trim();

        return {
            preservedHtml,
            cleanedText
        };
    } catch (err) {
        logger.error('Error cleaning email body:', err);
        return {
            preservedHtml: body,
            cleanedText: body
        };
    }
};

export const extractReadableText = (html) => {
    try {
        const $ = cheerio.load(html);
        // Remove unwanted elements
        $('style, script, link, meta, img').remove();
        // Get text content
        return $('body').text().replace(/\s+/g, ' ').trim();
    } catch (err) {
        logger.error('Error extracting readable text:', err);
        return html;
    }
};

export const getTextMetrics = (original, cleanedText, readableText) => {
    return {
        originalLength: original.length,
        cleanedLength: cleanedText.length,
        wordCount: readableText.split(/\s+/).length,
        sentences: readableText.split(/[.!?]+/g).length
    };
};

export const getUrlsFromPreservedHtml = (preservedHtml) => {
    try {
        const $ = cheerio.load(preservedHtml);
        const urls = [];
        
        $('a[href]').each((_, element) => {
            const $el = $(element);
            urls.push({
                href: $el.attr('href'),
                text: $el.text().trim()
            });
        });
        
        return urls;
    } catch (err) {
        logger.error('Error extracting URLs from preserved HTML:', err);
        return [];
    }
};