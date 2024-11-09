import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { connectDB, disconnectDB } from './src/config/db.js';
import analysisRoutes from './src/routes/analysis.routes.js';
import dnsRoutes from './src/routes/dns.routes.js';
import metricsRoutes from './src/routes/metrics.routes.js';
import whoisRoutes from './src/routes/whois.routes.js';
import { corsOptions } from './src/middleware/cors.middleware.js';
import logger from './src/config/logger.js';
import { startBackgroundJobs } from './src/jobs/scheduler.js';

dotenv.config(); // Load environment variables from .env file

const app = express();
const PORT = process.env.PORT || 8080; // Set the port for the server

app.use(cors(corsOptions));
app.use(express.json({ limit: '50mb' })); // Increase payload size limit

// Middleware to log incoming requests
app.use((req, res, next) => {
  logger.info(`Incoming ${req.method} request to ${req.originalUrl}`);
  next();
});

// Use routes
app.use('/analysis', analysisRoutes);
app.use('/dns', dnsRoutes);
app.use('/metrics', metricsRoutes);
app.use('/whois', whoisRoutes); // Use WHOIS routes

// Connect to the database and start the server
connectDB()
  .then(() => {
    app.listen(PORT, () => {
      logger.info(`Server is running on port ${PORT}`);
      startBackgroundJobs(); // Start background jobs after server is running
    });
  })
  .catch((error) => {
    logger.error('Error connecting to the database:', error);
  });

// Ensure the MongoDB connection is closed when the process exits
process.on('SIGINT', async () => {
  await disconnectDB();
  logger.info('Disconnected from MongoDB');
  process.exit(0);
});

process.on('SIGTERM', async () => {
  await disconnectDB();
  logger.info('Disconnected from MongoDB');
  process.exit(0);
});