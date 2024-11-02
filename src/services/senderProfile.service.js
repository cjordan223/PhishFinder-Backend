import { connectDB } from '../config/db.js';
import { extractCommonWords, linkAnalysis } from '../utils/emailAnalysisUtils.js'; // Assuming these functions are in emailAnalysisUtils.js

// Function to save or update sender profile in the database
export async function saveOrUpdateSenderProfile(emailData) {
  const db = await connectDB();
  const senderEmail = emailData.from;
  const domain = senderEmail.split('@')[1];

  const profile = await db.collection('sender_profiles').findOne({ sender: senderEmail });

  // Analyze email content for keywords, link risks, etc.
  const analyzedWords = extractCommonWords(emailData.body);
  const linkRisks = linkAnalysis(emailData.body);

  const emailEntry = {
    subject: emailData.subject,
    date: emailData.date,
    body: emailData.body,
    isSuspicious: emailData.isSuspicious,
    linkRisks,
    analyzedWords,
  };

  const linkRisksCount = {
    ipAddressLinks: linkRisks.filter(r => r.includes('IP address')).length,
    textUrlMismatch: linkRisks.filter(r => r.includes('Mismatched')).length,
  };

  if (profile) {
    // Update existing profile
    await db.collection('sender_profiles').updateOne(
      { sender: senderEmail },
      {
        $push: { emails: emailEntry },
        $addToSet: { commonWords: { $each: analyzedWords } },
        $inc: linkRisksCount,
      }
    );
  } else {
    // Create new profile
    await db.collection('sender_profiles').insertOne({
      sender: senderEmail,
      domain,
      emails: [emailEntry],
      commonWords: analyzedWords,
      linkRisksCount,
    });
  }
}