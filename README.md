# PhishFinder-Backend

Handles API and sensitive data. Email objects are sent to a cloud DB for storage and analytics.

[Front End Code](https://github.com/cjordan223/PhishFinder/)


Update with .env or will not work, then run:

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

This architecture allows for:

-   Scalable email processing

-   Real-time analysis

-   Secure data handling

-   Extensible analysis pipeline




