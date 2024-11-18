import { MongoClient } from 'mongodb';
import dotenv from 'dotenv';
import { createIndexes } from './db.indexes.js';
import { getEmailAuthenticationDetails } from '../services/dns.service.js';
import logger from '../config/logger.js';

dotenv.config();

const uri = process.env.MONGO_URI;
let client = null;
let db = null;

const options = {
  maxPoolSize: 50,
  minPoolSize: 10,
  maxIdleTimeMS: 60000,
  connectTimeoutMS: 5000,
  socketTimeoutMS: 45000,
};

export async function connectDB() {
  if (db) return db;

  try {
    client = await MongoClient.connect(uri, options);
    db = client.db('phishfinder');
    await createIndexes(db);
    logger.info('Connected to MongoDB with connection pooling');
    return db;
  } catch (error) {
    logger.error('MongoDB connection error:', error);
    throw error;
  }
}

export async function disconnectDB() {
  if (client) {
    await client.close();
    client = null;
    db = null;
    logger.info('Disconnected from MongoDB');
  }
}

export async function saveEmailAnalysis(emailData, processProfileImmediately = true) {
  const db = await connectDB();
  const emailsCollection = db.collection('emails');
  const authCollection = db.collection('domain_authentication');
  
  try {
    const existingEmail = await emailsCollection.findOne({ id: emailData.id });
    
    if (existingEmail) {
      logger.auth(`Email with id ${emailData.id} already exists. Skipping insertion.`);
      return existingEmail._id;
    }

    // Fetch domain authentication details
    const domainAuthentication = await getEmailAuthenticationDetails(emailData.sender.domain);
    logger.auth('Domain Authentication Details:', domainAuthentication);

    // Save domain authentication details to the separate collection
    const authResult = await authCollection.insertOne({
      domain: emailData.sender.domain,
      authentication: domainAuthentication,
      createdAt: new Date()
    });
    logger.auth('Domain Authentication Saved:', { insertedId: authResult.insertedId });

    const emailDataWithNull = {
      ...emailData,
      sender: {
        ...emailData.sender,
        whoisData: null
      },
      whoisLastUpdated: null,
      senderProfileProcessed: false,
      languageProfileProcessed: false,
      domain_authentication_id: authResult.insertedId
    };

    const result = await emailsCollection.insertOne(emailDataWithNull);
    logger.auth('Email analysis saved:', { insertedId: result.insertedId });

    if (processProfileImmediately) {
      try {
        const { saveOrUpdateSenderProfile } = await import('../services/senderProfile.service.js');
        await saveOrUpdateSenderProfile(emailData);
        await emailsCollection.updateOne(
          { _id: result.insertedId },
          { 
            $set: { 
              senderProfileProcessed: true,
              languageProfileProcessed: false
            }
          }
        );
      } catch (profileError) {
        logger.auth('Error processing sender profile:', profileError);
      }
    }

    return result.insertedId;

  } catch (error) {
    logger.auth('Error saving email analysis:', error);
    throw error;
  }
}

process.on('SIGINT', async () => {
  await disconnectDB();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  await disconnectDB();
  process.exit(0);
});

export async function checkDatabaseState() {
  const db = await connectDB();
  const emailCount = await db.collection('emails').countDocuments();
  const profileCount = await db.collection('sender_profiles').countDocuments();
  const unprocessedCount = await db.collection('emails').countDocuments({
    $or: [
      { senderProfileProcessed: { $ne: true } },
      { languageProfileProcessed: { $ne: true } }
    ]
  });
  
  console.log({
    totalEmails: emailCount,
    totalProfiles: profileCount,
    unprocessedEmails: unprocessedCount
  });
}

export async function getClient() {
  if (!client) {
    await connectDB();
  }
  return client;
}