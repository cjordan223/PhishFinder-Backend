// db.js

import { MongoClient } from 'mongodb';
import dotenv from 'dotenv';

dotenv.config();

const uri = process.env.MONGO_URI;
let client;
let db;

export async function connectDB() {
  try {
    if (!client) {
      client = new MongoClient(uri);
      await client.connect();
      db = client.db('phishfinder');
      console.log('Connected to MongoDB');
    }
    return db;
  } catch (error) {
    console.error('Error connecting to MongoDB:', error);
    process.exit(1);
  }
}

export async function disconnectDB() {
  if (client) {
    await client.close();
    client = null;
    console.log('Disconnected from MongoDB');
  }
}

// Function to save email analysis to the database, only if it doesn't exist
export async function saveEmailAnalysis(emailData) {
  const db = await connectDB();
  const emailsCollection = db.collection('emails');
  
  try {
    // Check if an email with the same id already exists
    const existingEmail = await emailsCollection.findOne({ id: emailData.id });
    
    if (existingEmail) {
      console.log(`Email with id ${emailData.id} already exists. Skipping insertion.`);
      return existingEmail._id; // Return the existing document's _id
    }

    // If it doesn't exist, insert the new email data
    const result = await emailsCollection.insertOne(emailData);
    console.log('Email analysis saved:', result.insertedId);
    return result.insertedId;

  } catch (error) {
    console.error('Error saving email analysis:', error);
    throw error;
  }
}
