## Business Email Compromise Attack Analysis

### Rule of Thumb
To effectively analyze Business Email Compromise (BEC) attacks, follow these guidelines:
1. **Verify Email Authenticity**: Check the sender's email address for any discrepancies or unusual domains.
2. **Analyze Email Content**: Look for urgent requests, unusual language, or requests for sensitive information.
3. **Monitor Financial Transactions**: Be cautious of unexpected financial transactions or changes in payment details.
4. **Check for Phishing Indicators**: Identify any phishing links or attachments within the email.

### Indicators to Look For
- **Unusual Login Activity**: Multiple login attempts from different locations or devices.
- **Email Forwarding Rules**: Unexpected forwarding rules set up in email accounts.
- **Changes in Communication Patterns**: Sudden changes in the tone or style of emails from known contacts.
- **Unauthorized Access**: Access to sensitive data or systems without proper authorization.

### Analyzing BEC Attacks Using SPL (Search Processing Language)
To analyze BEC attacks using SPL, consider the following queries:

1. **Identify Unusual Login Activity**:
    ```spl
    index=email_logs sourcetype="email" action="login" 
    | stats count by src_ip, user
    | where count > threshold
    ```

2. **Detect Email Forwarding Rules**:
    ```spl
    index=email_logs sourcetype="email" action="set_forwarding"
    | table _time, user, forwarding_address
    ```

3. **Monitor Financial Transactions**:
    ```spl
    index=financial_logs sourcetype="transactions"
    | stats sum(amount) by account, transaction_type
    | where transaction_type="wire_transfer" AND amount > threshold
    ```

4. **Check for Phishing Indicators**:
    ```spl
    index=email_logs sourcetype="email" action="received"
    | search subject="urgent" OR subject="payment" OR attachment="*.exe"
    | table _time, sender, subject, attachment
    ```

By following these guidelines and using the provided SPL queries, you can effectively identify and analyze BEC attacks within your organization.