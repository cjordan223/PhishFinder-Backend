import logger from '../config/logger.js';

export async function createIndexes(db) {
  try {
    // Create collections first
    await Promise.all([
      db.createCollection('emails'),
      db.createCollection('sender_profiles'),
      db.createCollection('whois'),
      db.createCollection('domain_authentication')
    ]).catch(err => {
      // Ignore "Collection already exists" errors
      if (!err.message.includes('Collection already exists')) {
        throw err;
      }
    });

    logger.info('Collections created or verified');

    // Drop existing indexes (except _id)
    await Promise.all([
      db.collection('emails').dropIndexes(),
      db.collection('sender_profiles').dropIndexes(),
      db.collection('whois').dropIndexes(),
      db.collection('domain_authentication').dropIndexes()
    ]).catch(err => {
      // Ignore "ns does not exist" errors for new collections
      if (!err.message.includes('ns does not exist')) {
        throw err;
      }
    });

    logger.info('Old indexes dropped');

    // Create fresh indexes
    await db.collection('emails').createIndexes([
      { key: { id: 1 }, unique: true, name: "email_id_idx" },
      { key: { 'sender.address': 1 }, name: "email_sender_address_idx" },
      { key: { 'sender.domain': 1 }, name: "email_sender_domain_idx" },
      { key: { 'receiver.address': 1 }, name: "email_receiver_address_idx" },
      { key: { 'receiver.domain': 1 }, name: "email_receiver_domain_idx" },
      { key: { timestamp: -1 }, name: "email_timestamp_idx" },
      { key: { senderProfileProcessed: 1 }, name: "email_profile_processed_idx" }
    ]);

    await db.collection('sender_profiles').createIndexes([
      { 
        key: { 'sender.address': 1 },
        unique: true,
        background: true,
        name: "sender_address_idx",
        partialFilterExpression: { 'sender.address': { $exists: true } }
      },
      { key: { 'sender.domain': 1 }, name: "sender_domain_idx" },
      { key: { lastUpdated: -1 }, name: "sender_last_updated_idx" }
    ]);

    await db.collection('whois').createIndexes([
      { key: { domain: 1 }, unique: true, name: "whois_domain_idx" },
      { key: { createdAt: -1 }, name: "whois_created_idx" }
    ]);

    await db.collection('domain_authentication').createIndexes([
      { 
        key: { domain: 1, createdAt: -1 },
        name: "domain_auth_compound_idx",
        background: true 
      },
      { key: { 'authentication.spf.status': 1 }, name: "domain_auth_spf_idx" },
      { key: { 'authentication.dkim.status': 1 }, name: "domain_auth_dkim_idx" },
      { key: { 'authentication.dmarc.policy': 1 }, name: "domain_auth_dmarc_idx" }
    ]);

    logger.info('All indexes created successfully');
  } catch (error) {
    logger.error('Error setting up database:', error);
    throw error; // Re-throw to handle in calling code
  }
}