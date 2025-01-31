# Identifying Phishing Payloads

## Rule of Thumb for Identifying Phishing Payloads

When analyzing potential phishing payloads, consider the following indicators:

1. **Suspicious Email Addresses**: Check for email addresses that do not match the sender's name or organization.
2. **Urgent or Threatening Language**: Look for language that creates a sense of urgency or fear.
3. **Unusual Attachments or Links**: Be cautious of unexpected attachments or links, especially if they prompt for credentials.
4. **Generic Greetings**: Phishing emails often use generic greetings like "Dear Customer" instead of your name.
5. **Spelling and Grammar Errors**: Many phishing emails contain noticeable spelling and grammar mistakes.
6. **Mismatched URLs**: Hover over links to see if the URL matches the expected destination.

## Analyzing Phishing Attacks Using SPL (Search Processing Language)

To analyze phishing attacks using SPL in a tool like Splunk, you can use the following queries:

### Example 1: Identifying Suspicious Email Addresses
```bash
index=email_logs sourcetype=email | search sender_email="*@suspiciousdomain.com"
```

### Example 2: Detecting Emails with Urgent Language
```bash
index=email_logs sourcetype=email | search "urgent" OR "immediate action required" OR "account suspended"
```

### Example 3: Finding Emails with Unusual Attachments
```bash
index=email_logs sourcetype=email | search attachment="*.exe" OR attachment="*.zip" OR attachment="*.scr"
```

### Example 4: Checking for Mismatched URLs
```bash
index=email_logs sourcetype=email | eval link_domain=mvindex(split(link, "/"), 2) | search link_domain!="expected-domain.com"
```

By using these SPL queries, you can filter and identify potential phishing emails and payloads within your organization's email logs.
