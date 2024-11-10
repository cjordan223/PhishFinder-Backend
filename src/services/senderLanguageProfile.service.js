import winkNLP from 'wink-nlp';
import model from 'wink-eng-lite-web-model';
import { connectDB } from '../config/db.js';
import logger from '../config/logger.js';

const nlp = winkNLP(model);

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
}

export const senderLanguageProfileService = new SenderLanguageProfileService();