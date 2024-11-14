# PhishFinder-Backend

Handles API and sensitive data. Email objects are sent to a cloud DB for storage and analytics.

[Front End Code](https://github.com/cjordan223/PhishFinder/)

## Project Structure

The project is organized as follows:

- **src**: Main source folder containing the core application files.
  - **__tests__**: Unit tests for various components.
  - **config**: Configuration files.
    - `db.js`: Database configuration and connection.
    - `logger.js`: Logger configuration.
  - **controllers**: Handles HTTP requests and responses.
    - `analysis.controller.js`: Controller for analysis endpoints.
    - `dns.controller.js`: Controller for DNS endpoints.
    - `metrics.controller.js`: Controller for metrics endpoints.
    - `whois.controller.js`: Controller for WHOIS endpoints.
  - **jobs**: Scheduled jobs and background tasks.
    - `scheduler.js`: Scheduler for running jobs.
    - `updateSenderProfiles.js`: Job for updating sender profiles.
  - **middleware**: Middleware functions.
    - `cors.middleware.js`: Handles CORS.
  - **routes**: Route definitions for different endpoints.
    - `analysis.routes.js`, `dns.routes.js`, etc.
  - **services**: Business logic and application services.
    - Includes `analysis.service.js`, `cache.service.js`, etc.
  - **utils**: Utility functions for common operations.
    - Examples: `emailParser.js`, `urlUtils.js`.
  - `server.js`: Main server entry point.

- **package.json**: Project metadata and dependencies.




_**^^This needs the .env file added with the secrets/keys/id's added to the root, or it won't run.**_
```
git clone <dir>
cd <dir>
npm install
docker compose up -d
```
Let the container start up for WHOIS server, then run
```
node index.js
```
## High Level

### Core Architecture

The project follows a client-server architecture:

1. Frontend (Vue.js)

-   User interface for email analysis

-   Real-time updates and visualizations

-   Authentication and profile management

-   Backend (Node.js)

-   Email processing and analysis

-   Language profiling

-   Security scoring

### Main Flow

-   User Authentication

-   User logs in/registers

-   OAuth2 authentication with email providers

-   Session management

**-   Email Processing**
    
    User Email → Gmail API → Raw Email Data → Parser → Structured Data
    

**-   Analysis Pipeline**
    
    Structured Email
    
    ↓
    
    Language Profile Analysis
    
    ↓
    
    Security Analysis
    
    ↓
    
    Risk Assessment
    

### Key Objects/Services

-   **EmailAnalysisService**

	  	Handles email parsing and initial processing

	   	Creates structured email objects

		Manages analysis workflow

-   **SenderLanguageProfileService**

		   Builds sender profiles

		  Topic analysis

		  Writing style analysis

	  	 Pattern recognition

- **SecurityAnalysisService**


	   URL analysis

	  Header analysis

	   Threat scoring

	   UserService

	   User management

	   Profile settings

	   Authentication

### Data Flow

User → Frontend → API Gateway

↓

Backend Services

↓

Database (MongoDB)

### Key Features

-   Language Analysis

-   Topic modeling

-   Sentiment analysis

-   Pattern detection

-   Security Checks

-   URL verification

-   Header analysis

-   Content scanning

-   Profile Building

-   Sender behavior patterns

-   Communication style

-   Historical analysis





