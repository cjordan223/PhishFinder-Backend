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
## To Do's

## 1. Email Metadata Collection
* Each time you fetch an email, gather and store the following metadata in your database:
* Sender Information:
    * Email Address: The sender's full email (e.g., mom@email.com).
    * Domain: Extracted from the email address (e.g., email.com).
    * Sender Name: If available in the headers.
* Authentication Information:
    * DMARC, SPF, and DKIM: These are DNS-based email authentication methods. They can help verify if an email actually came from the domain it claims to be from. DMARC, SPF, and DKIM data can often be found in email headers (e.g., Authentication-Results), which your backend can parse.
* Frequency and Trends:
    * Email Count: Track how many times you receive an email from this address or domain.
    * Last Seen: Timestamp of the most recent email received from this sender.
    * Subjects: Collect subject lines for pattern analysis.
* Content Patterns:
    * Keywords: Extract common keywords in the subject or body, especially if they match known phishing keywords.
    * Attachments and Links: Track if certain senders commonly send attachments or links, which could be useful for detecting phishing behavior.



