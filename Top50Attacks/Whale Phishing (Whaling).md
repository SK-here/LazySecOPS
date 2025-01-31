# Whale Phishing (Whaling) Attack Analysis

## Rule of Thumb to Identify Whale Phishing (Whaling) Attacks

Whale phishing, also known as whaling, targets high-profile executives or important individuals within an organization. Here are some indicators to look for:

1. **Unusual Requests**: Emails requesting urgent financial transactions, sensitive information, or confidential data.
2. **Spoofed Email Addresses**: Check for slight variations in email addresses that mimic legitimate ones.
3. **Personalized Content**: Emails that contain personal information about the target, indicating prior research.
4. **High-Level Language**: Professional and authoritative language that mimics the target's communication style.
5. **Attachments and Links**: Suspicious attachments or links that prompt the download of malware or direct to phishing sites.

## Analyzing Whale Phishing Attacks Using SPL (Search Processing Language)

To analyze these attacks using SPL in a tool like Splunk, you can use the following queries:

### 1. Identify Emails with Unusual Requests
```bash
index=email_logs sourcetype=email | search "urgent" OR "confidential" OR "sensitive" | table _time, sender, recipient, subject, message
```

### 2. Detect Spoofed Email Addresses
``````bash

index=email_logs sourcetype=email | regex sender=".*@example\.com" | table _time, sender, recipient, subject
```

### 3. Find Emails with Personalized Content
``````bash

index=email_logs sourcetype=email | search "CEO" OR "CFO" OR "executive" | table _time, sender, recipient, subject, message
```

### 4. Analyze High-Level Language
``````bash

index=email_logs sourcetype=email | search "authorize" OR "approve" OR "immediate" | table _time, sender, recipient, subject, message
```

### 5. Identify Suspicious Attachments and Links
``````bash

index=email_logs sourcetype=email | search "attachment" OR "link" | table _time, sender, recipient, subject, attachment, link
```

By using these SPL queries, you can filter and identify potential whale phishing attacks and take appropriate actions to mitigate them.