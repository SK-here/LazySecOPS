# Phishing Attack Identification and Analysis

## Rule of Thumb to Identify Phishing Attacks

1. **Suspicious Sender**: Check if the email is from an unknown or unusual sender.
2. **Generic Greetings**: Look for generic greetings like "Dear Customer" instead of your name.
3. **Urgent Language**: Be cautious of emails that create a sense of urgency or fear.
4. **Unusual Requests**: Verify if the email asks for sensitive information or credentials.
5. **Links and Attachments**: Hover over links to check their actual destination and be wary of unexpected attachments.
6. **Spelling and Grammar**: Look for poor spelling and grammar as indicators of phishing.
7. **Mismatched URLs**: Ensure that the URL in the email matches the legitimate website's URL.

## Indicators to Look For

- **Email Headers**: Analyze email headers for discrepancies.
- **Domain Names**: Check for slight variations in domain names.
- **IP Addresses**: Identify unusual IP addresses in email headers.
- **Content Analysis**: Look for common phishing phrases and patterns.
- **User Reports**: Pay attention to reports from users about suspicious emails.

## Analyzing Phishing Attacks Using SPL (Search Processing Language)

### Example SPL Queries

1. **Identify Emails from Suspicious Domains**
    ```bash
    index=email_logs sourcetype=email | search sender_domain IN ("suspiciousdomain.com", "phishingdomain.net")
    ```

2. **Detect Emails with Urgent Language**
    ```bash
    index=email_logs sourcetype=email | search subject="urgent" OR body="immediate action required"
    ```

3. **Find Emails with Unusual Attachments**
    ```bash
    index=email_logs sourcetype=email | search attachment_type!="pdf" AND attachment_type!="docx"
    ```

4. **Analyze User Reports**
    ```bash
    index=user_reports sourcetype=phishing_reports | stats count by sender_email
    ```

5. **Check for Mismatched URLs**
    ```bash
    index=email_logs sourcetype=email | eval url_domain=mvindex(split(url, "/"), 2) | search url_domain!=sender_domain
    ```

By following these guidelines and using SPL queries, you can effectively identify and analyze phishing attacks within your organization.