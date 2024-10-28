# PhishFinder-Backend

Handles API and sensitive data. Email objects are sent to a cloud DB for storage and analytics.

[Front End Code](https://github.com/cjordan223/PhishFinder/)


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

## 2. Database Schema for Email Profiling


| Field                | Type         | Description                                       |
|----------------------|--------------|---------------------------------------------------|
| `id`                 | UUID         | Unique identifier for each sender                 |
| `email`              | String       | Sender email address (e.g., mom@email.com)        |
| `domain`             | String       | Sender domain (e.g., email.com)                   |
| `name`               | String       | Sender name if available                          |
| `email_count`        | Integer      | Total number of emails received from this sender  |
| `last_seen`          | Timestamp    | Last email received from this sender              |
| `keywords`           | JSON/Array   | List of commonly used keywords in the sender’s emails |
| `attachments_count`  | Integer      | Number of times emails contained attachments      |
| `links_count`        | Integer      | Number of times emails contained links            |
| `authentication_results` | JSON/Object | DMARC, SPF, DKIM results                     |

