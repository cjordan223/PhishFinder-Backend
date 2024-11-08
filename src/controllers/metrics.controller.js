// src/controllers/metrics.controller.js
import { getMetricsData } from '../services/metrics.service.js';
import logger from '../config/logger.js';

// This controller handles the fetching of the metrics data
export const getMetrics = async (req, res) => {
  const { timeRange } = req.params;
  try {
    const metrics = await getMetricsData(timeRange);
    logger.info(`Fetched metrics for time range: ${timeRange}`);
    res.json(metrics);
  } catch (error) {
    logger.error('Error fetching metrics:', error);
    res.status(500).json({ error: 'Error fetching metrics' });
  }
};