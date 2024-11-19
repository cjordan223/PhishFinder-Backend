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