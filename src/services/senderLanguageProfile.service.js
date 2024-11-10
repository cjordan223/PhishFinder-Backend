import winkNLP from 'wink-nlp';
import model from 'wink-eng-lite-web-model';
import { connectDB } from '../config/db.js';
import logger from '../config/logger.js';

const nlp = winkNLP(model);
const its = nlp.its;
const as = nlp.as;

// Convert stop words to lowercase and expand the list
const STOP_WORDS = new Set([
    'the', 'and', 'in', 'of', 'to', 'a', 'is', 'that', 'for', 'it', 'with', 
    'as', 'by', 'on', 'are', 'at', 'be', 'this', 'was', 'have', 'has', 'from', 
    'or', 'an', 'they', 'which', 'can', 'also', 'but', 'been', 'their', 'more', 
    'had', 'when', 'where', 'who', 'will', 'would', 'what', 'there', 'we', 'all', 
    'no', 'yes', 'than', 'about', 'its', 'into', 'if', 'then', 'else', 'so',
    'such', 'just', 'these', 'those', 'any', 'some', 'each', 'very', 'our'
].map(word => word.toLowerCase()));

class SenderLanguageProfileService {
    constructor() {
        this.cache = new Map();
    }
        async analyzeSenderEmails(senderEmail, emails) {
            try {
                logger.info(`Starting language analysis for sender ${senderEmail} with ${emails.length} emails`);
                
                emails.forEach(email => {
                    const emailBody = email.body || email.content?.cleanedBody;
                    logger.debug(`Email ${email.id} content status:`, {
                        hasBody: !!emailBody,
                        bodyLength: emailBody?.length || 0
                    });
                });
                const db = await connectDB();
                const senderProfile = await db.collection('sender_profiles')
                    .findOne({ 'sender.address': senderEmail });
                
                const allEmails = [...emails];
                if (senderProfile?.emails) {
                    allEmails.push(...senderProfile.emails);
                }
                let languageProfile = {
                    wordFrequency: {},
                    averageSentenceLength: 0,
                    commonPhrases: [],
                    topicAnalysis: [],
                    lastUpdated: new Date()
                };
                let totalSentences = 0;
                let totalWords = 0;
                // Track phrases (3-5 word sequences)
                const phraseFrequency = {};
    
                for (const email of allEmails) {
                    const emailBody = email.body || email.content?.cleanedBody;
                    if (!emailBody) {
                        logger.warn(`Email ${email.id} has no body content, skipping`);
                        continue;
                    }
                    logger.debug(`Analyzing email ${email.id} content`);
                    const doc = nlp.readDoc(emailBody);
                    
                    const sentences = doc.sentences().out();
                    totalSentences += sentences.length;
                    
                    const words = doc.tokens().out();
                    totalWords += words.length;
                    words.forEach(word => {
                        languageProfile.wordFrequency[word] = (languageProfile.wordFrequency[word] || 0) + 1;
                    });
                    // Extract and count common phrases (3-5 word sequences)
                    for (const sentence of sentences) {
                        const words = sentence.split(/\s+/);
                        
                        // Generate n-grams (phrases of 3-5 words)
                        for (let n = 3; n <= 5; n++) {
                            for (let i = 0; i <= words.length - n; i++) {
                                const phrase = words.slice(i, i + n).join(' ').toLowerCase();
                                phraseFrequency[phrase] = (phraseFrequency[phrase] || 0) + 1;
                            }
                        }
                    }
                    // Basic topic analysis using keyword clustering
                    languageProfile.topicAnalysis = this.processTopicAnalysis(doc, languageProfile);
                    logger.debug(`Topic analysis for ${senderEmail}:`, languageProfile.topicAnalysis);
                    // Add most common phrases (frequency > 2)
                    languageProfile.commonPhrases = Object.entries(phraseFrequency)
                        .filter(([_, freq]) => freq > 2)
                        .map(([phrase, frequency]) => ({
                            phrase,
                            frequency
                        }))
                        .sort((a, b) => b.frequency - a.frequency)
                        .slice(0, 40); // Keep top 40 phrases
                }
                languageProfile.averageSentenceLength = totalWords / totalSentences;
                logger.info(`Language profile stats for ${senderEmail}:`, {
                    totalEmails: allEmails.length,
                    totalSentences,
                    totalWords,
                    averageSentenceLength: languageProfile.averageSentenceLength,
                    uniqueWords: Object.keys(languageProfile.wordFrequency).length
                });
                await this.saveSenderLanguageProfile(senderEmail, languageProfile);
            } catch (error) {
                logger.error(`Error in language analysis for ${senderEmail}:`, error);
                throw error;
            }
        }
     
    async saveSenderLanguageProfile(senderEmail, profile) {
        const db = await connectDB();
        try {
            await db.collection('sender_profiles').updateOne(
                { 'sender.address': senderEmail },
                { 
                    $set: { 
                        languageProfile: profile,
                        languageProfileLastUpdated: new Date()
                    }
                }
            );
            
            this.cache.set(`sender_profile:${senderEmail}`, profile);
        } catch (error) {
            logger.error('Error saving sender language profile:', error);
            throw error;
        }
    }

    async getSenderProfile(senderEmail) {
        const cached = this.cache.get(`sender_profile:${senderEmail}`);
        if (cached) return cached;

        const db = await connectDB();
        const profile = await db.collection('sender_profiles')
            .findOne({ 'sender.address': senderEmail });
        
        if (profile?.languageProfile) {
            this.cache.set(`sender_profile:${senderEmail}`, profile.languageProfile);
            return profile.languageProfile;
        }

        return null;
    }

        processTopicAnalysis(doc, languageProfile) {
        logger.debug('Starting processTopicAnalysis');
        
        const topics = new Map();
        const tokens = doc.tokens();
        const sentencesObj = doc.sentences();
        const sentences = sentencesObj.out(); // Keep array version for compatibility
        
        // Extract meaningful keywords
        const keywords = tokens
            .filter((token) => {
                const text = token.out().toLowerCase();
                const pos = token.out(its.pos);
                
                logger.debug('Token analysis:', {
                    text,
                    pos,
                    isValid: (pos === 'NOUN' || pos === 'VERB' || pos === 'ADJ') && 
                            !STOP_WORDS.has(text) &&
                            text.length > 2,
                    isStopWord: STOP_WORDS.has(text)
                });
                
                return (pos === 'NOUN' || pos === 'VERB' || pos === 'ADJ') && 
                       !STOP_WORDS.has(text) &&
                       text.length > 2;
            })
            .out();

        logger.debug('Extracted keywords:', {
            keywordCount: keywords.length,
            sampleKeywords: keywords.slice(0, 5)
        });

        // Group related words by sentence context
        for (const keyword of keywords) {
            const keywordLower = keyword.toLowerCase();
            
            // Find matching sentences (using array version for includes)
            const matchingSentenceIndexes = sentences
                .map((s, i) => s.toLowerCase().includes(keywordLower) ? i : -1)
                .filter(i => i !== -1);
                
            // Process each matching sentence using wink-nlp objects
            matchingSentenceIndexes.forEach(index => {
                const sentence = sentencesObj.itemAt(index);
                const related = sentence.tokens()
                    .filter((token) => {
                        const text = token.out().toLowerCase();
                        const pos = token.out(its.pos);
                        return (pos === 'NOUN' || pos === 'VERB' || pos === 'ADJ') && 
                               text !== keywordLower &&
                               !STOP_WORDS.has(text) &&
                               text.length > 2;
                    })
                    .out();
                
                if (!topics.has(keyword)) {
                    topics.set(keyword, new Set());
                }
                related.forEach(word => topics.get(keyword).add(word));
            });
        }

        // Convert topics map to array format with improved scoring
        const topicAnalysis = Array.from(topics.entries())
            .map(([topic, related]) => ({
                topic,
                relatedTerms: Array.from(related),
                frequency: languageProfile.wordFrequency[topic.toLowerCase()] || 1,
                score: (languageProfile.wordFrequency[topic.toLowerCase()] || 1) * 
                       (Array.from(related).length + 1)
            }))
            .filter(topic => topic.relatedTerms.length > 0)
            .sort((a, b) => b.score - a.score)
            .slice(0, 15);

        logger.debug('Final topic analysis:', {
            topicsFound: topicAnalysis.length,
            topTopics: topicAnalysis.slice(0, 3)
        });

        return topicAnalysis;
    }
}

export const senderLanguageProfileService = new SenderLanguageProfileService();