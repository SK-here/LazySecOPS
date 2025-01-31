# Identifying and Analyzing Watering Hole Attacks

## Rule of Thumb to Identify Watering Hole Attacks

1. **Unusual Traffic Patterns**: Look for unusual traffic to websites that are not commonly visited by your organization.
2. **Compromised Websites**: Identify if legitimate websites frequently visited by your organization have been compromised.
3. **Malicious Code**: Check for the presence of malicious code or scripts on websites that are commonly accessed by your employees.
4. **Phishing Indicators**: Be aware of phishing attempts that direct users to compromised websites.
5. **User Reports**: Pay attention to user reports of unusual behavior or pop-ups when visiting certain websites.

## Indicators to Look For

- **Unusual Domain Requests**: Requests to domains that are not typically accessed by your organization.
- **Changes in Website Behavior**: Legitimate websites behaving differently, such as redirecting to unknown sites or showing unexpected pop-ups.
- **Malware Alerts**: Alerts from security tools indicating the presence of malware on websites.
- **Suspicious Network Traffic**: Unusual outbound traffic patterns, especially to unknown or suspicious IP addresses.

## Analyzing Watering Hole Attacks Using SPL (Search Processing Language)

```bash
index=web_traffic
| search uri_path="*"
| stats count by uri_path, src_ip, dest_ip
| where count > threshold
| table uri_path, src_ip, dest_ip, count
```

```bash
index=malware_alerts
| search signature="*watering hole*"
| stats count by signature, src_ip, dest_ip
| table signature, src_ip, dest_ip, count
```

```bash
index=network_traffic
| search dest_ip="*"
| stats count by dest_ip, src_ip
| where count > threshold
| table dest_ip, src_ip, count
```

These SPL queries help identify unusual web traffic patterns, malware alerts related to watering hole attacks, and suspicious network traffic that may indicate a watering hole attack.
