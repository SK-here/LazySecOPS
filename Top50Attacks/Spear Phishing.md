# Identifying Spear Phishing Attacks

## Rule of Thumb for Identifying Spear Phishing Attacks

1. **Personalization**: Look for emails that are highly personalized with specific information about you or your organization.
2. **Urgency**: Be cautious of messages that create a sense of urgency or pressure to act quickly.
3. **Suspicious Links or Attachments**: Check for unexpected links or attachments, especially from unknown senders.
4. **Unusual Requests**: Be wary of requests for sensitive information or financial transactions.
5. **Email Address**: Verify the sender's email address for any discrepancies or unusual domains.
6. **Grammar and Spelling**: Look for poor grammar or spelling mistakes, which can be indicators of phishing.

## Indicators to Look For

- Unusual sender email addresses
- Unexpected attachments or links
- Requests for sensitive information
- High urgency or pressure to act
- Inconsistencies in email content or formatting

## Analyzing Spear Phishing Attacks Using SPL (Search Processing Language)

To analyze spear phishing attacks using SPL, you can use the following queries:

### Example SPL Queries

1. **Identify Emails with Suspicious Attachments**:
    ```bash
    index=email_logs sourcetype=email | search attachment=* | stats count by sender, attachment
    ```

2. **Find Emails with Urgent Language**:
    ```bash
    index=email_logs sourcetype=email | search "urgent" OR "immediate" OR "asap" | stats count by sender, subject
    ```

3. **Detect Emails from Unusual Domains**:
    ```bash
    index=email_logs sourcetype=email | regex sender=".*@(?!yourcompany\.com).*" | stats count by sender
    ```

4. **Identify Requests for Sensitive Information**:
    ```bash
    index=email_logs sourcetype=email | search "password" OR "credentials" OR "account" | stats count by sender, subject
    ```

By using these queries, you can filter and identify potential spear phishing emails and take appropriate actions to mitigate the risks.
