# Compromised Credentials Attack Analysis

## Rule of Thumb
When dealing with compromised credentials, consider the following rule of thumb:
1. **Monitor for Unusual Activity**: Look for login attempts from unusual locations or at unusual times.
2. **Check for Multiple Failed Login Attempts**: Multiple failed login attempts can indicate a brute force attack.
3. **Analyze Account Behavior**: Sudden changes in account behavior, such as accessing sensitive data or performing unauthorized actions, can be a red flag.
4. **Review Access Logs**: Regularly review access logs for any anomalies or unauthorized access.

## Indicators to Look For
- **Unusual Login Locations**: Logins from IP addresses or geographic locations that are not typical for the user.
- **Time of Access**: Logins at odd hours that do not match the user's normal activity patterns.
- **Multiple Failed Logins**: A high number of failed login attempts followed by a successful login.
- **Unusual Account Activity**: Access to sensitive data or systems that the user does not normally access.
- **Changes in User Settings**: Unauthorized changes to user account settings or permissions.

## Analyzing Attacks Using SPL (Search Processing Language)
To analyze compromised credentials attacks using SPL, you can use the following queries:

### 1. Detecting Unusual Login Locations
```bash
index=authentication sourcetype=access_combined
| stats count by user, src_ip, geo_location
| where geo_location != "expected_location"
```

### 2. Identifying Multiple Failed Login Attempts
```bash

index=authentication sourcetype=access_combined
| stats count by user, status
| where status="failed"
| where count > 5
```

### 3. Monitoring Unusual Account Activity
```bash
index=authentication sourcetype=access_combined
| stats count by user, action
| where action="access_sensitive_data"
| where count > threshold
```

### 4. Reviewing Access Logs for Anomalies
```bash
index=authentication sourcetype=access_combined
| stats count by user, action, time
| where action="login"
| where time != "normal_hours"
```

By using these SPL queries, you can effectively monitor and analyze potential compromised credentials attacks within your organization.