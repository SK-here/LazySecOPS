# Web Session Cookie Theft Analysis

## Rule of Thumb to Identify Web Session Cookie Theft Attack

1. **Unusual Login Locations**: Monitor for logins from unexpected geographic locations.
2. **Multiple Logins**: Look for multiple logins from different IP addresses in a short time frame.
3. **Session Hijacking**: Check for session IDs being used from different IP addresses or devices.
4. **User Complaints**: Pay attention to user reports of unexpected account activity.
5. **Anomalous Behavior**: Identify unusual user behavior such as accessing sensitive data or performing unauthorized actions.

## Indicators to Look For

- **IP Address Changes**: Sudden changes in IP addresses during a session.
- **User Agent Changes**: Different user agents for the same session ID.
- **Session Duration**: Abnormally long or short session durations.
- **Failed Login Attempts**: Multiple failed login attempts followed by a successful login.
- **Unusual Activity**: Access to resources or data that the user typically does not access.

## Analyzing Attacks Using SPL (Search Processing Language)

```bash
index=web_logs sourcetype=access_combined
| transaction session_id maxspan=30m
| search NOT [search index=web_logs sourcetype=access_combined | stats count by session_id | where count < 2 | fields session_id]
| stats values(clientip) as client_ips, values(useragent) as user_agents, dc(clientip) as ip_count, dc(useragent) as ua_count by session_id
| where ip_count > 1 OR ua_count > 1
| table session_id, client_ips, user_agents, ip_count, ua_count
```

This SPL query helps identify sessions with multiple IP addresses or user agents, which are indicators of potential session hijacking.
