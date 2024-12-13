PhishFinder Backend - Quick Start Guide

Key Files:
-----------
1. src/controllers/analysis.controller.js
   - Handles email analysis requests.
   - Performs URL extraction, Safe Browsing checks, pattern analysis, and DNS authentication.

2. src/services/analysis.service.js
   - Provides helper functions for email analysis.
   - Includes functions for SPF, DMARC extraction, and response requirement determination.

3. src/services/senderLanguageProfile.service.js
   - Analyzes sender emails for language profiling.
   - Builds language profiles based on email content.

4. src/services/senderProfile.service.js
   - Manages sender profiles.
   - Updates profiles with email data and security metrics.

5. src/utils/urlAnalyzer.js
   - Analyzes URLs within email bodies.
   - Detects domain mismatches and checks for redirects.

6. src/config/db.js
   - Configures MongoDB connection.
   - Provides functions to connect and disconnect from the database.

7. src/jobs/updateSenderProfiles.js
   - Processes unprocessed emails to update sender profiles.
   - Runs language analysis and updates database records.

8. package.json
   - Lists project dependencies and scripts.
   - Defines the entry point for the application.

Starting the Application:
-------------------------
1. Clone the repository:
   git clone https://github.com/cjordan223/PhishFinder-Backend.git
   cd PhishFinder-Backend

2. Install dependencies:
   npm install

3. Create a .env file in the root directory with the following variables:
   MONGO_URI=your_mongodb_uri
   SAFE_BROWSING_API_KEY=your_google_api_key
   API_TOKEN=your_api_token
   PORT=8080

4. Start Docker containers:
   docker compose up -d

5. Start the server:
   node index.js

Note: Ensure that the MongoDB and any other required services are running before starting the server.
