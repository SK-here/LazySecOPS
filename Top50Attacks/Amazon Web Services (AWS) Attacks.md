# Amazon Web Services (AWS) Attacks

## Rule of Thumb for AWS Attacks
When analyzing AWS attacks, consider the following rule of thumb:
1. **Monitor Access Logs**: Regularly review AWS CloudTrail logs for unusual activities.
2. **Check IAM Policies**: Ensure IAM policies follow the principle of least privilege.
3. **Enable Multi-Factor Authentication (MFA)**: Enforce MFA for all users.
4. **Monitor Network Traffic**: Use AWS VPC Flow Logs to monitor network traffic.
5. **Regular Audits**: Conduct regular security audits and vulnerability assessments.
6. **Automate Security**: Use AWS Config and AWS Security Hub for continuous monitoring.

## Indicators to Look For
1. **Unusual Login Locations**: Logins from unexpected geographic locations.
2. **Excessive API Calls**: High volume of API calls in a short period.
3. **Unauthorized Resource Access**: Access to resources that are not typically used.
4. **Changes in Security Groups**: Unauthorized modifications to security group rules.
5. **Data Exfiltration**: Large data transfers to unknown IP addresses.
6. **Disabled Logging**: Sudden disabling of CloudTrail or other logging services.

## Analyzing AWS Attacks Using SPL (Search Processing Language)
To analyze AWS attacks using SPL, you can use the following queries:

### Example 1: Detect Unusual Login Locations
```bash
index=aws_cloudtrail eventName=ConsoleLogin
| stats count by sourceIPAddress userIdentity.arn
| where count > 10
| table sourceIPAddress userIdentity.arn count
```

### Example 2: Identify Excessive API Calls
```bash
index=aws_cloudtrail
| stats count by eventName userIdentity.arn
| where count > 100
| table eventName userIdentity.arn count
```

### Example 3: Monitor Unauthorized Resource Access
```bash
index=aws_cloudtrail
| search eventName=Describe* OR eventName=List* OR eventName=Get*
| stats count by eventName userIdentity.arn
| where count > 50
| table eventName userIdentity.arn count
```

### Example 4: Detect Changes in Security Groups
```bash
index=aws_cloudtrail eventName=AuthorizeSecurityGroupIngress OR eventName=RevokeSecurityGroupIngress
| stats count by eventName userIdentity.arn
| table eventName userIdentity.arn count
```

### Example 5: Identify Data Exfiltration
```bash
index=aws_vpc_flow_logs
| stats sum(bytes) as total_bytes by src_ip dest_ip
| where total_bytes > 1000000000
| table src_ip dest_ip total_bytes
```

### Example 6: Detect Disabled Logging
```bash
index=aws_cloudtrail eventName=StopLogging OR eventName=DeleteTrail
| stats count by eventName userIdentity.arn
| table eventName userIdentity.arn count
```

By using these SPL queries, you can effectively monitor and analyze potential AWS attacks.