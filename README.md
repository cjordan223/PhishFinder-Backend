
# PhishFinder Backend

## Technical Architecture

### Core Technologies
- Node.js/Express.js Backend server
- MongoDB for data persistence
- Docker for containerization
- Natural Language Processing for content analysis using Wink NLP

### Analysis Pipeline

#### 1. Email Processing & Analysis
- **Content Cleaning & Extraction**
  - HTML sanitization and text extraction
  - Metadata parsing
  - URL extraction


- **Security Analysis**
  - Pattern matching for suspicious content
  - URL/link analysis
  - Domain authentication


#### 2. Authentication Verification
- **DNS Record Analysis**
  - SPF record verification
  - DKIM validation
  - DMARC policy checking


#### 3. Sender Profiling
- **Language Analysis**
  - Topic modeling
  - Writing style analysis
  - Pattern recognition


#### 4. URL Analysis
- **Link Safety Verification**
  - Google Safe Browsing API integration
  - URL mismatch detection
  - Domain reputation checking


## Installation

1. Clone the repository:
	```
	git clone https://github.com/cjordan223/PhishFinder-Backend.git
	cd PhishFinder-Backend
	npm install
	```

2. Configure environment variables:
Create a `.env` file with:

	- MONGO_URI=your_mongodb_uri from Mongo Atlas
    - SAFE_BROWSING_API_KEY= GMAIL API Key
    - AI_API_TOKEN=your_AI_token (copyleaks, winston etc)
    - PORT=8080
3. Start the server and service
	```
	docker compose up -d
	node index.js
	```

## API Endpoints

### Analysis Endpoints
- `POST /analysis/analyze-email`: Analyze email content
- `GET /analysis/email/:id`: Retrieve email analysis
- `GET /analysis/sender/:email`: Get sender profile
- `POST /analysis/ai-analyze`: AI-powered content analysis

### DNS Endpoints
- `GET /dns/:domain`: Fetch DNS authentication records
- `POST /dns/verify`: Verify email authentication

### WHOIS Endpoints
- `GET /whois/:domain`: Fetch WHOIS data
- `POST /whois/:domain/:emailId`: Update WHOIS data

## Security Features

### 1. Content Analysis
- Suspicious pattern detection
- Keyword analysis
- Language profiling
- Content categorization

### 2. URL Security
- Safe Browsing API integration
- URL mismatch detection
- Domain reputation checking
- Redirect chain analysis

### 3. Sender Authentication
- SPF record verification
- DKIM validation
- DMARC policy checking
- Domain authentication status

### 4. Behavioral Analysis
- Sender profiling
- Communication pattern analysis
- Historical data analysis
- Risk assessment

## Data Storage

### MongoDB Collections
- `emails`: Email analysis results
- `sender_profiles`: Sender behavior profiles
- `whois`: Domain WHOIS data
- `metrics`: Analysis metrics

## Error Handling
- Comprehensive error logging
- Request validation
- Rate limiting
- API error responses

## Future Enhancements
- Enhanced AI analysis capabilities
- Real-time threat intelligence integration
- Advanced behavioral analysis
- Extended metrics and reporting
- Machine learning model integration

## Contributing
1. Fork the repository
2. Create a feature branch
3. Commit changes
4. Push to the branch
5. Create a Pull Request

## License
This project is licensed under the MIT License.

