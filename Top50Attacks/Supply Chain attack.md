# Identifying Supply Chain Attacks

## Rule of Thumb
To identify a supply chain attack, consider the following indicators:
- Unexpected or unauthorized changes in software or hardware components.
- Anomalous network traffic patterns, especially involving third-party vendors.
- Unusual account activities, such as logins from unfamiliar locations or at odd times.
- Presence of new, unrecognized files or executables.
- Sudden changes in system performance or behavior.

## Indicators to Look For
- **Code Integrity**: Check for unauthorized changes in code repositories.
- **Network Traffic**: Monitor for unusual outbound connections to third-party services.
- **User Activity**: Look for irregular login attempts or access patterns.
- **System Changes**: Identify unexpected installations or updates.
- **Performance Metrics**: Observe any degradation in system performance.

## Analyzing Attacks Using SPL (Search Processing Language)
To analyze supply chain attacks using SPL, you can use the following queries:

### Example 1: Detecting Unauthorized Changes
```bash
index=main sourcetype=code_changes
| where change_type="unauthorized"
| stats count by file_name, user
```

### Example 2: Monitoring Network Traffic
```bash
index=network sourcetype=traffic_logs
| where dest_ip IN (third_party_ips)
| stats count by src_ip, dest_ip, dest_port
```

### Example 3: Identifying Unusual User Activity
```bash
index=auth sourcetype=login_attempts
| where login_time < relative_time(now(), "-1h") OR login_time > relative_time(now(), "+1h")
| stats count by user, src_ip
```

### Example 4: Detecting New Executables
```bash
index=main sourcetype=file_monitor
| where file_type="executable" AND action="created"
| stats count by file_name, user
```

### Example 5: Monitoring System Performance
```bash
index=performance sourcetype=system_metrics
| where cpu_usage > 80 OR memory_usage > 80
| stats avg(cpu_usage), avg(memory_usage) by host
```

By using these queries, you can effectively monitor and analyze potential supply chain attacks within your organization.