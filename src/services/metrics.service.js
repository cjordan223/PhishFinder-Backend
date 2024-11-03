import { connectDB } from '../config/db.js';

export async function getMetricsData(timeRange) {
  try {
    const db = await connectDB();
    const emailsCollection = db.collection('emails');

    const endDate = new Date();
    const startDate = new Date();
    switch (timeRange) {
      case '7d':
        startDate.setDate(endDate.getDate() - 7);
        break;
      case '30d':
        startDate.setDate(endDate.getDate() - 30);
        break;
      case '90d':
        startDate.setDate(endDate.getDate() - 90);
        break;
      default:
        startDate.setDate(endDate.getDate() - 7);
    }

    console.log(`Querying emails from ${startDate.toISOString()} to ${endDate.toISOString()}`);

    const metrics = await emailsCollection.aggregate([
      {
        $match: {
          timestamp: {
            $gte: startDate,
            $lte: endDate,
          },
        },
      },
      {
        $group: {
          _id: null,
          totalEmails: { $sum: 1 },
        },
      },
    ]).toArray();

    console.log('Metrics:', metrics);

    return metrics[0] || {
      totalEmails: 0,
    };
  } catch (error) {
    console.error('Error fetching metrics:', error);
    throw new Error('Error fetching metrics');
  }
}