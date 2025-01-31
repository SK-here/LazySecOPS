# Shadow IT Analysis

## Rule of Thumb to Identify Shadow IT Attacks

1. **Unapproved Software/Hardware**: Look for any software or hardware that has not been approved by the IT department.
2. **Unusual Network Traffic**: Monitor for unusual spikes in network traffic or connections to unknown external servers.
3. **Unauthorized Access**: Check for access attempts to sensitive data or systems by unauthorized users.
4. **Data Transfers**: Be wary of large data transfers to external locations.
5. **Anomalous Behavior**: Identify any unusual behavior patterns from users or devices.

## Indicators to Look For

- **Unrecognized Devices**: Devices that are not registered with the IT department.
- **Unapproved Applications**: Applications that are not listed in the company's approved software list.
- **Unusual Access Patterns**: Access to systems or data at odd hours or from unusual locations.
- **Data Exfiltration**: Large volumes of data being transferred out of the network.
- **Security Alerts**: Alerts from security systems indicating potential breaches or anomalies.

## Analyzing Attacks Using SPL (Search Processing Language)

### Example SPL Queries

1. **Identify Unapproved Software Installations**
    ```bash
    index=main sourcetype=software_installation
    | search NOT [inputlookup approved_software.csv]
    | table _time, host, user, software_name
    ```

2. **Monitor Unusual Network Traffic**
    ```bash
    index=main sourcetype=network_traffic
    | stats sum(bytes) by src_ip, dest_ip
    | where sum(bytes) > 1000000
    | table _time, src_ip, dest_ip, sum(bytes)
    ```

3. **Detect Unauthorized Access Attempts**
    ```bash
    index=main sourcetype=authentication
    | search action=failed
    | stats count by user, src_ip
    | where count > 5
    | table _time, user, src_ip, count
    ```

4. **Identify Large Data Transfers**
    ```bash
    index=main sourcetype=data_transfer
    | stats sum(bytes) by src_ip, dest_ip
    | where sum(bytes) > 5000000
    | table _time, src_ip, dest_ip, sum(bytes)
    ```

5. **Detect Anomalous User Behavior**
    ```bash
    index=main sourcetype=user_activity
    | stats count by user, activity
    | where count > 100
    | table _time, user, activity, count
    ```

By following these guidelines and using the provided SPL queries, you can effectively identify and analyze potential Shadow IT attacks within your organization.