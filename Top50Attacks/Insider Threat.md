# Insider Threat Analysis

## Rule of Thumb for Insider Threats and Attacks
1. **Understand the Context**: Know the business processes and the normal behavior of employees.
2. **Monitor User Activity**: Keep an eye on user activities, especially those with elevated privileges.
3. **Data Access Patterns**: Look for unusual access to sensitive data.
4. **Behavioral Changes**: Notice any changes in behavior, such as accessing systems at odd hours.
5. **Anomalous Network Traffic**: Identify unusual network traffic patterns.
6. **Use of Unauthorized Devices**: Detect the use of unauthorized devices or software.

## Indicators to Look For
- **Unusual Login Times**: Logins during non-working hours.
- **Access to Unrelated Data**: Accessing data not related to the user's role.
- **Multiple Failed Login Attempts**: Repeated failed login attempts.
- **Data Exfiltration**: Large data transfers to external locations.
- **Privilege Escalation**: Attempts to gain higher access levels.
- **Use of Personal Email**: Sending company data to personal email accounts.

## Analyzing Attacks Using SPL (Search Processing Language)
### Example SPL Queries

1. **Unusual Login Times**
    ```bash
    index=main sourcetype=access_combined | where date_hour < 6 OR date_hour > 18 | stats count by user
    ```

2. **Access to Unrelated Data**
    ```bash
    index=main sourcetype=access_combined | where resource IN ("sensitive_data1", "sensitive_data2") | stats count by user
    ```

3. **Multiple Failed Login Attempts**
    ```bash
    index=main sourcetype=access_combined action=failure | stats count by user
    ```

4. **Data Exfiltration**
    ```bash
    index=main sourcetype=network_traffic | where bytes_out > 1000000 | stats sum(bytes_out) by dest_ip
    ```

5. **Privilege Escalation**
    ```bash
    index=main sourcetype=access_combined action=privilege_escalation | stats count by user
    ```

6. **Use of Personal Email**
    ```bash
    index=main sourcetype=email_logs | where recipient_domain="gmail.com" OR recipient_domain="yahoo.com" | stats count by sender
    ```

By following these guidelines and using SPL queries, you can effectively monitor and analyze insider threats within your organization.