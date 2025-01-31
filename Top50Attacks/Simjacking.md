## Rule of Thumb to Identify Simjacking Attacks

### Indicators to Look For:
1. **Unusual Account Activity**: Unexpected changes in account settings or unauthorized transactions.
2. **Sudden Loss of Service**: Victims may suddenly lose cellular service as the attacker transfers the number to a new SIM card.
3. **Unauthorized Requests**: Requests for personal information or SIM card changes that the user did not initiate.
4. **Alerts from Service Providers**: Notifications from your mobile carrier about SIM card changes or new device activations.

### Analyzing Simjacking Attacks Using SPL (Search Processing Language):
To analyze potential Simjacking attacks using SPL, you can use the following queries:

```bash
index=network_logs "SIM card change" OR "new device activation" 
| stats count by user, action, timestamp 
| where count > 1
```

```bash
index=account_activity "unauthorized transaction" OR "account settings change" 
| stats count by user, action, timestamp 
| where count > 1
```

These queries help identify suspicious activities related to SIM card changes and unauthorized account actions.