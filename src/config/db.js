import { MongoClient } from 'mongodb';
import dotenv from 'dotenv';
import { createIndexes } from './db.indexes.js';

dotenv.config();

const uri = process.env.MONGO_URI; // MongoDB connection URI
let client = null;
let db = null;

const options = {
  maxPoolSize: 50,
  minPoolSize: 10,
  maxIdleTimeMS: 60000,
  connectTimeoutMS: 5000,
  socketTimeoutMS: 45000,
};

// Function to connect to MongoDB
export async function connectDB() {
  if (db) return db;

  try {
    client = await MongoClient.connect(uri, options);
    db = client.db('phishfinder');
    
    // Create indexes on first connection
    await createIndexes(db);
    
    console.log('Connected to MongoDB with connection pooling');
    return db;
  } catch (error) {
    console.error('MongoDB connection error:', error);
    throw error;
  }
}

// Function to disconnect from MongoDB
export async function disconnectDB() {
  if (client) {
    await client.close();
    client = null;
    db = null;
    console.log('Disconnected from MongoDB');
  }
}

// Function to save email analysis to the database, only if it doesn't exist
export async function saveEmailAnalysis(emailData, processProfileImmediately = true) {
  const db = await connectDB();
  const emailsCollection = db.collection('emails');
  
  try {
    // Check if an email with the same id already exists
    const existingEmail = await emailsCollection.findOne({ id: emailData.id });
    
    if (existingEmail) {
      console.log(`Email with id ${emailData.id} already exists. Skipping insertion.`);
      return existingEmail._id;
    }

    // Ensure sender object has whoisData initialized as null
    const emailDataWithNull = {
      ...emailData,
      sender: {
        ...emailData.sender,
        whoisData: null
      },
      whoisLastUpdated: null,
      senderProfileProcessed: false
    };

    // If it doesn't exist, insert the new email data
    const result = await emailsCollection.insertOne(emailDataWithNull);
    console.log('Email analysis saved:', result.insertedId);

    // Optionally process the sender profile immediately
    if (processProfileImmediately) {
      try {
        const { saveOrUpdateSenderProfile } = await import('../services/senderProfile.service.js');
        await saveOrUpdateSenderProfile(emailData);
        // Mark as processed
        await emailsCollection.updateOne(
          { _id: result.insertedId },
          { $set: { senderProfileProcessed: true }}
        );
      } catch (profileError) {
        console.error('Error processing sender profile:', profileError);
        // Don't throw the error - we still want to return the saved email ID
      }
    }

    return result.insertedId;

  } catch (error) {
    console.error('Error saving email analysis:', error);
    throw error;
  }
}

// Ensure the MongoDB connection is closed when the process exits
process.on('SIGINT', async () => {
  await disconnectDB();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  await disconnectDB();
  process.exit(0);
});

// Add this function to help debug
export async function checkDatabaseState() {
  const db = await connectDB();
  const emailCount = await db.collection('emails').countDocuments();
  const profileCount = await db.collection('sender_profiles').countDocuments();
  const unprocessedCount = await db.collection('emails').countDocuments({ senderProfileProcessed: { $ne: true } });
  
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