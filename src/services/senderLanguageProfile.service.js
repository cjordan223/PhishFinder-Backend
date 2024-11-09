import winkNLP from 'wink-nlp';
import model from 'wink-eng-lite-web-model';
import { connectDB } from '../config/db.js';
import { cleanEmailBody, extractReadableText } from '../utils/textCleaner.js';
import logger from '../config/logger.js';
import { analyzeSuspiciousPatterns } from './analysis.service.js';

const nlp = winkNLP(model);
const its = nlp.its;
const as = nlp.as;

class SenderLanguageProfileService {
    constructor() {
        this.cache = new Map(); // Simple in-memory cache
    }

    async analyzeSenderEmails(senderEmail, emails) {
        try {
            // Get the sender profile to access all historical emails
            const db = await connectDB();
            const senderProfile = await db.collection('sender_profiles')
                .findOne({ 'sender.address': senderEmail });
            
            // Combine existing emails with new ones for analysis
            const allEmails = senderProfile ? 
                [...senderProfile.emails, ...emails] : 
                emails;

            const profile = {
                wordFrequency: {},
                commonPhrases: {},
                entityTypes: {},
                averageSentenceLength: 0,
                totalEmails: allEmails.length,
                lastUpdated: new Date(),
                commonEntities: {},
                sentimentTrend: [],
                formalityScore: 0
            };

            let totalSentences = 0;
            let totalWords = 0;

            for (const email of allEmails) {
                if (!email.body) {
                    logger.warn(`Email ${email.id} has no body content, skipping`);
                    continue;
                }

                const doc = nlp.readDoc(email.body);

                // Process sentences
                const sentences = doc.sentences().out();
                totalSentences += sentences.length;

                // Process tokens and words
                const tokens = doc.tokens().out();
                const words = tokens.filter(token => 
                    doc.tokens().itemAt(tokens.indexOf(token)).out(its.type) === 'word'
                );
                totalWords += words.length;

                // Update word frequency
                words.forEach(word => {
                    const lemma = doc.tokens().itemAt(tokens.indexOf(word)).out(its.lemma);
                    profile.wordFrequency[lemma] = (profile.wordFrequency[lemma] || 0) + 1;
                });

                // Process entities
                const entities = doc.entities().out(its.type);
                entities.forEach(entity => {
                    profile.entityTypes[entity] = (profile.entityTypes[entity] || 0) + 1;
                });

                // Calculate sentiment using pattern matching instead
                const suspiciousPatterns = analyzeSuspiciousPatterns(email.body, email.subject);
                const sentiment = suspiciousPatterns.length ? -1 : 0; // Simple negative/neutral sentiment
                profile.sentimentTrend.push({
                    timestamp: email.timestamp,
                    score: sentiment,
                    patterns: suspiciousPatterns
                });
            }

            // Calculate averages and normalize
            profile.averageSentenceLength = totalWords / totalSentences;
            
            // Get top words (exclude common stop words)
            const tempDoc = nlp.readDoc(Object.keys(profile.wordFrequency).join(' '));
            profile.wordFrequency = Object.fromEntries(
                Object.entries(profile.wordFrequency)
                    .filter(([word]) => !tempDoc.tokens().itemAt(0).out(its.stopWordFlag))
                    .sort(([,a], [,b]) => b - a)
                    .slice(0, 100)
            );

            // Save to database and cache
            await this.saveSenderLanguageProfile(senderEmail, profile);

            return profile;

        } catch (error) {
            logger.error('Error analyzing sender emails:', error);
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
                },
                { upsert: true }
            );
            
            // Also cache it
            await this.cache.set(`sender_profile:${senderEmail}`, profile);
        } catch (error) {
            logger.error('Error saving sender language profile:', error);
            throw error;
        }
    }

    async getSenderProfile(senderEmail) {
        // Try cache first
        const cached = this.cache.get(`sender_profile:${senderEmail}`);
        if (cached) return cached;

        // If not in cache, get from database
        const db = await connectDB();
        const profile = await db.collection('sender_profiles')
            .findOne({ 'sender.address': senderEmail });
        
        if (profile?.languageProfile) {
            this.cache.set(`sender_profile:${senderEmail}`, profile.languageProfile);
            return profile.languageProfile;
        }

        return null;
    }
}

export const senderLanguageProfileService = new SenderLanguageProfileService();