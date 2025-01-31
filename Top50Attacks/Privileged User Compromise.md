# Identifying Privileged User Compromise Attacks

## Rule of Thumb

To identify a Privileged User Compromise attack, look for the following indicators:

1. **Unusual Login Patterns**: Logins from unusual locations or at odd times.
2. **Multiple Failed Login Attempts**: Repeated failed login attempts followed by a successful login.
3. **Access to Sensitive Data**: Unusual access to sensitive data or systems.
4. **Changes in User Behavior**: Sudden changes in user behavior, such as accessing systems they don't usually use.
5. **Elevation of Privileges**: Unauthorized elevation of privileges.
6. **Unusual Network Traffic**: Unusual network traffic patterns, such as large data transfers.
7. **Disabled Security Tools**: Security tools being disabled or tampered with.

## Analyzing Attacks Using SPL (Search Processing Language)

### Example SPL Queries

1. **Unusual Login Patterns**
    ```bash
    index=main sourcetype=access_combined user=* 
    | stats count by user, src_ip 
    | where count > 10
    ```

2. **Multiple Failed Login Attempts**
    ```bash
    index=main sourcetype=access_combined status=failed 
    | stats count by user 
    | where count > 5
    ```

3. **Access to Sensitive Data**
    ```bash
    index=main sourcetype=access_combined uri="/sensitive_data/*" 
    | stats count by user 
    | where count > 1
    ```

4. **Changes in User Behavior**
    ```bash
    index=main sourcetype=access_combined user=* 
    | timechart span=1d count by user 
    | where count > avg(count) * 2
    ```

5. **Elevation of Privileges**
    ```bash
    index=main sourcetype=access_combined action="elevate_privileges" 
    | stats count by user 
    | where count > 0
    ```

6. **Unusual Network Traffic**
    ```bash
    index=main sourcetype=network_traffic 
    | stats sum(bytes) by src_ip, dest_ip 
    | where sum(bytes) > 1000000
    ```

7. **Disabled Security Tools**
    ```bash
    index=main sourcetype=security_tools status=disabled 
    | stats count by tool_name 
    | where count > 0
    ```

By using these SPL queries, you can identify potential indicators of Privileged User Compromise attacks and take appropriate actions to mitigate them.