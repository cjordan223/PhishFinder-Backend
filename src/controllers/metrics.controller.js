// src/controllers/metrics.controller.js
import { getMetricsData } from '../services/metrics.service.js';

//this controller handles the fetching of the metrics data

export const getMetrics = async (req, res) => {
  const { timeRange } = req.params;
  try {
    const metrics = await getMetricsData(timeRange);
    
    res.json(metrics);
  } catch (error) {
    console.error('Error fetching metrics:', error);
    res.status(500).json({ error: 'Error fetching metrics' });
  }
};