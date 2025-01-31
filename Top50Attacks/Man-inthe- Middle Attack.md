# Man-in-the-Middle Attack Analysis

## Rule of Thumb for Man-in-the-Middle Attack

To analyze a Man-in-the-Middle (MITM) attack, here are some key indicators to watch for and a basic rule of thumb to follow:

### Rule of Thumb
1. **Encryption:** Ensure all communications are encrypted using strong protocols (e.g., HTTPS, TLS).
2. **Network Monitoring:** Continuously monitor network traffic for anomalies.
3. **Authentication:** Implement strong authentication mechanisms, including multi-factor authentication (MFA).

### Indicators of a Man-in-the-Middle Attack
1. **Unusual Network Activity:** Unexplained spikes in network traffic or unknown IP addresses.
2. **Certificate Warnings:** Unexpected SSL/TLS certificate changes or warnings.
3. **ARP Cache Changes:** Unusual ARP (Address Resolution Protocol) cache activity indicating possible poisoning.
4. **Duplicate or Suspicious Packets:** Duplicate TCP/UDP packets or packets with altered headers Attacks using Wireshark - HackBlue](https://hackblue.org/pages/mitm_attacks_using_wireshark.html).

### Analyzing Man-in-the-Middle Attacks using SPL (Search Processing Language—used in Splunk)
Here's a simple example for Splunk:

#### Detecting ARP Spoofing
```bash
index=network sourcetype=bro_conn 
| eval ip_src=coalesce(orig_ip, src_ip), ip_dst=coalesce(resp_ip, dst_ip)
| stats values(mac_src) by ip_src ip_dst
| where mvcount(mac_src) > 1
| table ip_src ip_dst mac_src
```
This SPL query identifies instances where multiple MAC addresses are associated with a single IP address, often indicating ARP spoofing.

#### Identifying Suspicious Certificates
```bash
index=network sourcetype=ssl
| eval issue=if(ssl_ca != "TrustedCA", 1, 0)
| search issue=1
| table src_ip src_port dest_ip dest_port ssl_ca
```
This SPL query detects connections using untrusted SSL/TLS certificates.

Would you like any more detail on detecting or analyzing specific attack types?