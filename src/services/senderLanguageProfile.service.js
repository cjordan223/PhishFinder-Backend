import winkNLP from 'wink-nlp';
import model from 'wink-eng-lite-web-model';
import { connectDB } from '../config/db.js';
import logger from '../config/logger.js';

const nlp = winkNLP(model);
const its = nlp.its;
const as = nlp.as;

const STOP_WORDS = new Set(['the', 'and', 'in', 'of', 'to', 'a', 'is', 'that', 'for', 'it', 'with', 'as', 'by', 'on', 'are', 'at', 'be', 'this', 'was', 'have', 'has', 'from', 'or', 'an', 'they', 'which', 'can', 'also', 'but', 'been', 'their', 'more', 'had', 'when', 'where', 'who', 'will', 'would', 'what', 'there', 'we', 'all', 'no', 'yes', 'than', 'about']);

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

                // Add most common phrases (frequency > 2)
                languageProfile.commonPhrases = Object.entries(phraseFrequency)
                    .filter(([_, freq]) => freq > 2)
                    .map(([phrase, frequency]) => ({
                        phrase,
                        frequency
                    }))
                    .sort((a, b) => b.frequency - a.frequency)
                    .slice(0, 20); // Keep top 20 phrases
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
        const topics = new Map();
        const tokens = doc.tokens();
        const keywords = tokens
            .filter((token) => {
                const text = token.out().toLowerCase();
                const pos = token.out(its.pos);
                return (pos === 'noun' || pos === 'verb') && 
                       !STOP_WORDS.has(text) &&
                       text.length > 2;
            })
            .out();
        
        // Group related words by semantic similarity
        for (const keyword of keywords) {
            const sentence = doc.tokens()
                .filter(t => t.parentSentence() === keyword.parentSentence())
                .out();
                
            const related = sentence
                .filter(word => 
                    word !== keyword && 
                    !STOP_WORDS.has(word.toLowerCase()) &&
                    word.length > 2
                );
            
            if (!topics.has(keyword)) {
                topics.set(keyword, new Set());
            }
            related.forEach(word => topics.get(keyword).add(word));
        }

        // Convert topics map to array format with better scoring
        return Array.from(topics.entries())
            .map(([topic, related]) => ({
                topic,
                relatedTerms: Array.from(related),
                frequency: languageProfile.wordFrequency[topic] || 1,
                score: (languageProfile.wordFrequency[topic] || 1) * 
                       (Array.from(related).length + 1)
            }))
            .sort((a, b) => b.score - a.score)
            .slice(0, 15); // Keep top 15 topics
    }
}

export const senderLanguageProfileService = new SenderLanguageProfileService();