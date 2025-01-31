# Pass the Hash Analysis

## Rule of Thumb to Identify Pass the Hash

Pass the Hash (PtH) attacks involve an attacker capturing and using a hashed password to authenticate as a user without knowing the actual password. Here are some indicators to look for:

1. **Unusual Authentication Patterns**: Look for logins from unusual locations or at unusual times.
2. **Multiple Logins**: Multiple logins from different machines using the same hash.
3. **Lateral Movement**: Signs of lateral movement within the network, especially using administrative credentials.
4. **Event Logs**: Windows Event Logs, particularly Security Event IDs 4624 (Logon) and 4672 (Special privileges assigned to new logon).

## Analyzing Pass the Hash Attacks Using SPL (Search Processing Language)

To analyze PtH attacks using SPL, you can use the following queries:

### 1. Identify Unusual Logins
``` bash
index=wineventlog EventCode=4624 LogonType=3
| stats count by IpAddress, AccountName
| where count > 10
```

### 2. Detect Multiple Logins from Different Machines
```bash
index=wineventlog EventCode=4624
| stats dc(IpAddress) as unique_ips by AccountName
| where unique_ips > 1
```

### 3. Track Lateral Movement
```bash
index=wineventlog EventCode=4624 LogonType=3
| transaction AccountName maxspan=1h
| search eventcount > 3
```

### 4. Monitor for Special Privileges
```bash
index=wineventlog EventCode=4672
| stats count by AccountName
| where count > 5
```

These queries can help you identify potential PtH attacks by highlighting unusual authentication patterns and lateral movement within your network.