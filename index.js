import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { connectDB } from './src/config/db.js';
import analysisRoutes from './src/routes/analysis.routes.js';
import dnsRoutes from './src/routes/dns.routes.js';
import metricsRoutes from './src/routes/metrics.routes.js';
import whoisRoutes from './src/routes/whois.routes.js'; // Import WHOIS routes
import { corsOptions } from './src/middleware/cors.middleware.js';

dotenv.config(); // Load environment variables from .env file

const app = express();
const PORT = process.env.PORT || 8080; // Set the port for the server

app.use(cors(corsOptions));
app.use(express.json());

// Use routes
app.use('/analysis', analysisRoutes);
app.use('/dns', dnsRoutes);
app.use('/metrics', metricsRoutes);
app.use('/whois', whoisRoutes); // Use WHOIS routes

// Connect to the database and start the server
connectDB()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server is running on port ${PORT}`);
    });
  })
  .catch((error) => {
    console.error('Failed to connect to the database:', error);
    process.exit(1); // Exit the process with a failure code
  });