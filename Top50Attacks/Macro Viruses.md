# Macro Virus Attack Analysis

## Rule of Thumb for Macro Virus Attack
1. **Email Attachments**: Be cautious of unexpected email attachments, especially those with macros.
2. **File Extensions**: Watch for files with extensions like `.docm`, `.xlsm`, etc.
3. **Unexpected Macros**: Be wary of documents prompting to enable macros.
4. **Unusual Behavior**: Look for unusual system behavior after opening a document.
5. **Antivirus Alerts**: Pay attention to antivirus alerts related to macro-enabled files.

## Indicators to Look For
- **Suspicious Email**: Emails from unknown senders with attachments.
- **File Properties**: Documents with macros that are not part of normal business operations.
- **System Changes**: Unexpected changes in system settings or new files created.
- **Network Traffic**: Unusual outbound network traffic after opening a document.

## Analyzing Attacks Using SPL (Search Processing Language)
To analyze macro virus attacks using SPL in a tool like Splunk, you can use the following queries:

### Example SPL Queries
1. **Identify Suspicious Emails**:
    ```bash
    index=email_logs sourcetype=email | search subject="*macro*" OR attachment="*.docm" OR attachment="*.xlsm"
    ```

2. **Detect Macro Execution**:
    ```bash
    index=system_logs sourcetype=windows_event_log EventCode=4688 | search "WINWORD.EXE" OR "EXCEL.EXE" | stats count by User, CommandLine
    ```

3. **Monitor Network Traffic**:
    ```bash
    index=network_traffic sourcetype=firewall_logs | search dest_port=80 OR dest_port=443 | stats count by src_ip, dest_ip
    ```

4. **Check for Antivirus Alerts**:
    ```bash
    index=antivirus_logs sourcetype=av_logs | search "macro virus" | stats count by file_name, user
    ```

By following these guidelines and using the provided SPL queries, you can effectively monitor and analyze potential macro virus attacks in your organization.