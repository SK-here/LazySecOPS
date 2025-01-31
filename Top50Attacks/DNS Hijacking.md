# DNS Hijacking Attack Analysis

## Rule of Thumb for DNS Hijacking Attack
1. **Unexpected DNS Changes**: Monitor for unauthorized changes in DNS settings.
2. **Unusual Traffic Patterns**: Look for abnormal spikes or drops in DNS traffic.
3. **Suspicious DNS Queries**: Identify queries to unfamiliar or malicious domains.
4. **Altered IP Addresses**: Check for IP addresses that do not match known DNS records.
5. **User Complaints**: Pay attention to reports of redirected or failed connections.

## Indicators to Look For
- **DNS Configuration Changes**: Unauthorized modifications in DNS records.
- **Traffic Redirection**: Traffic being redirected to unknown or malicious IP addresses.
- **Increased DNS Query Failures**: Higher rates of DNS resolution failures.
- **Unusual DNS Query Patterns**: Queries to domains that are not typically accessed by users.

## Analyzing DNS Hijacking Attacks Using SPL (Search Processing Language)
```bash
index=dns_logs
| search "dns_change" OR "dns_redirect" OR "dns_failure"
| stats count by src_ip, dest_ip, query, status
| where status="failure" OR status="redirect"
| table src_ip, dest_ip, query, status, count
```

This SPL query searches for DNS changes, redirects, and failures in the DNS logs, then counts occurrences by source IP, destination IP, query, and status, and filters for failure or redirect statuses.
