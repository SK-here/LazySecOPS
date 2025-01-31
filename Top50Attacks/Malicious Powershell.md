# Malicious PowerShell Attack Analysis

As a cybersecurity analyst, it is crucial to identify and analyze malicious PowerShell activities. Here are some rules of thumb and indicators to look for, along with how to analyze these attacks using SPL (Search Processing Language) in Splunk.

## Indicators of Malicious PowerShell Activity

1. **Unusual PowerShell Execution**:
    - PowerShell scripts running from non-standard directories.
    - PowerShell processes spawning other suspicious processes.

2. **Encoded Commands**:
    - Look for the use of `-EncodedCommand` which is often used to obfuscate malicious scripts.

3. **Network Connections**:
    - PowerShell making network connections, especially to external IP addresses.

4. **Suspicious Modules**:
    - Loading of uncommon or suspicious PowerShell modules.

5. **High Volume of PowerShell Activity**:
    - Anomalous increase in PowerShell activity on a host.

6. **Script Block Logging**:
    - Review script block logs for suspicious or obfuscated code.

## Analyzing Malicious PowerShell Attacks Using SPL

Here are some example SPL queries to help identify malicious PowerShell activities:

### Detecting Encoded Commands
```bash
index=main sourcetype=WinEventLog:Security EventCode=4688 
| where process_name="powershell.exe" AND process="*EncodedCommand*"
| table _time, host, user, process_name, process
```

### Identifying Network Connections
```bash
index=main sourcetype=WinEventLog:Security EventCode=5156 
| where process_name="powershell.exe"
| table _time, host, user, process_name, dest_ip, dest_port
```

### Monitoring Script Block Logging
```bash
index=main sourcetype=WinEventLog:Microsoft-Windows-PowerShell/Operational 
| where EventCode=4104
| table _time, host, user, script_block_text
```

### Detecting Unusual PowerShell Modules
```bash
index=main sourcetype=WinEventLog:Microsoft-Windows-PowerShell/Operational 
| where EventCode=4103
| table _time, host, user, module_name
```

By monitoring these indicators and using the provided SPL queries, you can effectively identify and analyze potential malicious PowerShell activities within your organization.
