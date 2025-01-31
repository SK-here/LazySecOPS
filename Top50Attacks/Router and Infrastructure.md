# Router and Infrastructure Attack Analysis

## Rule of Thumb for Identifying Attacks

1. **Unusual Traffic Patterns**: Look for spikes in traffic, unusual IP addresses, or unexpected protocols.
2. **Unauthorized Access**: Check for login attempts from unknown sources or at odd hours.
3. **Configuration Changes**: Monitor for unauthorized changes to router settings or firmware.
4. **Service Disruptions**: Be aware of frequent disconnections or degraded performance.
5. **Log Anomalies**: Look for irregularities in system logs, such as repeated failed login attempts or unexpected reboots.

## Indicators to Look For

- **Unusual IP Addresses**: Traffic from IPs not typically associated with your network.
- **High Traffic Volume**: Sudden increases in traffic that could indicate a DDoS attack.
- **Repeated Login Failures**: Multiple failed login attempts could signal a brute force attack.
- **Configuration Changes**: Unauthorized changes to router settings or firmware updates.
- **Service Interruptions**: Frequent disconnections or slow network performance.

## Analyzing Attacks Using SPL (Search Processing Language)

### Example SPL Queries

1. **Detecting Unusual Traffic Patterns**
    ```bash
    index=network_traffic | stats count by src_ip, dest_ip, protocol | where count > threshold
    ```

2. **Identifying Unauthorized Access**
    ```bash
    index=auth_logs action=failure | stats count by src_ip, user | where count > threshold
    ```

3. **Monitoring Configuration Changes**
    ```bash
    index=config_changes | stats count by change_type, user | where change_type="unauthorized"
    ```

4. **Detecting Service Disruptions**
    ```bash
    index=network_logs | stats count by event_type | where event_type="disconnection" OR event_type="degradation"
    ```

5. **Analyzing Log Anomalies**
    ```bash
    index=system_logs | stats count by event_type, src_ip | where event_type="failed_login" OR event_type="unexpected_reboot"
    ```

By following these guidelines and using SPL queries, you can effectively identify and analyze router and infrastructure attacks.