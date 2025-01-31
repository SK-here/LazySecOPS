# Credential Reuse Attack

## Rule of Thumb
Credential reuse attacks occur when attackers use stolen credentials from one service to gain unauthorized access to another service. To mitigate these attacks, follow these rules of thumb:
- Enforce strong, unique passwords for each service.
- Implement multi-factor authentication (MFA).
- Regularly monitor and review access logs.
- Educate users about the risks of password reuse.

## Indicators to Look For
When analyzing potential credential reuse attacks, look for the following indicators:
- Multiple failed login attempts from the same IP address.
- Successful logins from unusual locations or devices.
- Sudden changes in user behavior, such as accessing sensitive data they don't usually access.
- Logins at unusual times for the user.

## Analyzing Attacks Using SPL (Search Processing Language)
To analyze credential reuse attacks using SPL in a tool like Splunk, you can use the following queries:

### Detecting Multiple Failed Login Attempts
```bash
index=authentication sourcetype=access_combined action=failure
| stats count by src_ip
| where count > 5
```

### Identifying Successful Logins from Unusual Locations
```bash
index=authentication sourcetype=access_combined action=success
| stats dc(src_ip) as unique_ips by user
| where unique_ips > 1
```

### Monitoring Sudden Changes in User Behavior
```bash
index=authentication sourcetype=access_combined action=success
| stats count by user, uri_path
| eventstats avg(count) as avg_count by user
| where count > 2 * avg_count
```

### Detecting Logins at Unusual Times
```bash
index=authentication sourcetype=access_combined action=success
| eval hour=strftime(_time, "%H")
| stats count by user, hour
| where hour < 6 OR hour > 22
```

By using these SPL queries, you can identify potential credential reuse attacks and take appropriate actions to mitigate them.