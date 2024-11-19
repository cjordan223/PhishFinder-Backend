import logger from '../config/logger.js';

export async function createIndexes(db) {
  try {
    // Emails collection indexes
    await db.collection('emails').createIndexes([
      { key: { id: 1 }, unique: true },
      { key: { 'sender.address': 1 } },
      { key: { 'sender.domain': 1 } },
      { key: { 'receiver.address': 1 } },
      { key: { 'receiver.domain': 1 } },
      { key: { timestamp: -1 } },
      { key: { senderProfileProcessed: 1 } }
    ]);

    // Clean duplicates and create sender profiles indexes
    const duplicates = await findAndCleanDuplicateSenderProfiles(db);
    if (duplicates > 0) {
      logger.info(`Cleaned up ${duplicates} duplicate sender profiles`);
    }

    await db.collection('sender_profiles').createIndexes([
      { 
        key: { 'sender.address': 1 },
        unique: true,
        background: true,
        partialFilterExpression: { 'sender.address': { $exists: true } }
      },
      { key: { 'sender.domain': 1 } },
      { key: { lastUpdated: -1 } }
    ]);

    // WHOIS collection indexes
    await db.collection('whois').createIndexes([
      { key: { domain: 1 }, unique: true },
      { key: { createdAt: -1 } }
    ]);

    // Domain authentication collection indexes
    await db.collection('domain_authentication').createIndexes([
      { 
        key: { domain: 1, createdAt: -1 }, 
        unique: true,
        background: true 
      },
      { key: { 'authentication.spf.status': 1 } },
      { key: { 'authentication.dkim.status': 1 } },
      { key: { 'authentication.dmarc.policy': 1 } }
    ]);

    logger.info('Database indexes created successfully');
  } catch (error) {
    logger.error('Error creating database indexes:', error);
    logger.warn('Continuing without all indexes...');
  }
}

async function findAndCleanDuplicateSenderProfiles(db) {
  const pipeline = [
    {
      $group: {
        _id: '$sender.address',
        count: { $sum: 1 },
        docs: { $push: '$_id' }
      }
    },
    {
      $match: {
        count: { $gt: 1 }
      }
    }
  ];

  const duplicates = await db.collection('sender_profiles')
    .aggregate(pipeline)
    .toArray();

  let cleanedCount = 0;
  for (const dup of duplicates) {
    // Keep the first document, remove others
    const [keepId, ...removeIds] = dup.docs;
    await db.collection('sender_profiles').deleteMany({
      _id: { $in: removeIds }
    });
    cleanedCount += removeIds.length;
  }

  return cleanedCount;
} 

