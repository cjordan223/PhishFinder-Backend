// index.js
import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { connectDB } from './src/config/db.js';
import analysisRoutes from './src/routes/analysis.routes.js';
import dnsRoutes from './src/routes/dns.routes.js';
import metricsRoutes from './src/routes/metrics.routes.js';
import whoisRoutes from './src/routes/whois.routes.js';
import { corsOptions } from './src/middleware/cors.middleware.js';
import logger from './src/config/logger.js';

dotenv.config(); // Load environment variables from .env file

const app = express();
const PORT = process.env.PORT || 8080; // Set the port for the server

app.use(cors(corsOptions));
app.use(express.json());

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