import { getMetricsData } from '../services/metrics.service.js';
import logger from '../config/logger.js';

export const getMetrics = async (req, res) => {
  const { timeRange } = req.params;
  try {
    const metrics = await getMetricsData(timeRange);
    logger.info(`Fetched metrics for time range: ${timeRange}`);
    res.json(metrics); // Ensure JSON response
  } catch (error) {
    logger.error('Error fetching metrics:', error);
    res.status(500).json({ error: 'Error fetching metrics' }); // Ensure JSON response
  }
};