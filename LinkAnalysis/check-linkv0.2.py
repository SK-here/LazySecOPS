#!/usr/bin/env python3

'''
@Author: Saksham Trivedi
@Description: Comprehensive URL analysis with multi-IP checks
@Requirements: pip install python-whois whois requests dnspython
'''

import requests
import whois
import socket
import re
import dns.resolver
import base64
from urllib.parse import urlparse 

# API Configuration
VIRUSTOTAL_API_KEY = "ea1ab0b53b2a0a75e04649ef90e09c98aeeeca76c217aebc6e834a225d369100"
ABUSEIPDB_API_KEY = "d363dc3477bfef7b806689b1a78eedcbaaf3e1fa121b579bd54a6363b762b1c9c7154252c0ed5921"
MXTOOLBOX_API_KEY = "986a295c-96fc-45d0-955f-efcb76602277" 

def check_virustotal(resource, resource_type="url"):
    """Check URL/IP/Domain on VirusTotal"""
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    endpoint = {
        "url": "urls",
        "ip": "ip_addresses",
        "domain": "domains"
    }[resource_type]

    try:
        if resource_type == "url":
            encoded = base64.urlsafe_b64encode(resource.encode()).decode().strip("=")
            url = f"https://www.virustotal.com/api/v3/{endpoint}/{encoded}"
        else:
            url = f"https://www.virustotal.com/api/v3/{endpoint}/{resource}"
        
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            result = response.json()
            stats = result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            return malicious
        return None
    except Exception as e:
        print(f"[!] VirusTotal Error: {str(e)}")
        return None

def check_abuseipdb(ip):
    """Check IP reputation on AbuseIPDB"""
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    
    try:
        response = requests.get(url, headers=headers, params={"ipAddress": ip})
        if response.status_code == 200:
            result = response.json()
            return result.get('data', {})
        return None
    except Exception as e:
        print(f"[!] AbuseIPDB Error: {str(e)}")
        return None

def check_mxtoolbox(command, argument):
    """MXToolbox API integration"""
    url = "https://api.mxtoolbox.com/api/v1/Lookup"
    headers = {"Authorization": f"Bearer {MXTOOLBOX_API_KEY}"}
    
    try:
        response = requests.get(url, headers=headers, params={"command": command, "argument": argument})
        if response.status_code == 200:
            return response.json()
        return None
    except Exception as e:
        print(f"[!] MXToolbox Error: {str(e)}")
        return None

def resolve_dns(domain):
    """Resolve all DNS records for comprehensive analysis"""
    results = {"A": [], "MX": [], "SPF": []}
    
    try:
        # A Records
        answers = dns.resolver.resolve(domain, 'A')
        results["A"] = [str(r) for r in answers]
    except Exception as e:
        pass
    
    try:
        # MX Records
        answers = dns.resolver.resolve(domain, 'MX')
        for r in answers:
            mx_host = str(r.exchange).rstrip('.')
            try:
                mx_ips = dns.resolver.resolve(mx_host, 'A')
                results["MX"].extend([str(ip) for ip in mx_ips])
            except Exception:
                pass
    except Exception as e:
        pass
    
    try:
        # TXT Records for SPF
        answers = dns.resolver.resolve(domain, 'TXT')
        for r in answers:
            record = ''.join(r.strings)
            if "v=spf1" in record:
                results["SPF"] = re.findall(r'ip[46]:([\d./:]+)', record)
                break
    except Exception as e:
        pass
    
    return results

def analyze_url(target):
    """Main analysis function"""
    print(f"\n{' Starting Analysis ':=^80}")
    
    # Extract domain from URL
    if "://" in target:
        domain = urlparse(target).netloc  # Now properly imported
    else:
        domain = target.split('/')[0]
    
    print(f"\n[+] WHOIS Analysis for {domain}:")
    try:
        w = whois.whois(domain)
        print(f"  Registrar: {w.registrar}")
        print(f"  Created: {w.creation_date}")
        print(f"  Expires: {w.expiration_date}")
    except Exception as e:
        print(f"  [!] WHOIS Error: {str(e)}")
    
    # Comprehensive DNS Resolution
    print(f"\n[+] DNS Analysis for {domain}:")
    dns_info = resolve_dns(domain)
    all_ips = set(dns_info["A"] + dns_info["MX"] + dns_info["SPF"])
    
    if all_ips:
        print(f"  Found {len(all_ips)} unique IP addresses:")
        for ip in all_ips:
            print(f"  - {ip}")
    else:
        print("  No IP addresses found!")
    
    # IP Analysis
    for ip in all_ips:
        print(f"\n{' IP Analysis ':-^60}")
        print(f"  Analyzing: {ip}")
        
        # AbuseIPDB Check
        abuse_data = check_abuseipdb(ip)
        if abuse_data:
            print(f"  Abuse Confidence: {abuse_data.get('abuseConfidenceScore', 0)}%")
            print(f"  Total Reports: {abuse_data.get('totalReports', 0)}")
        
        # VirusTotal Check
        vt_score = check_virustotal(ip, "ip")
        if vt_score is not None:
            print(f"  VirusTotal Flags: {vt_score}")
        
        # MXToolbox Blacklist Check
        bl_data = check_mxtoolbox("blacklist", ip)
        if bl_data and bl_data.get('IsBlacklisted'):
            print(f"  Blacklisted on {bl_data['ListedOnCount']} lists:")
            for bl in bl_data['Blacklists'][:3]:
                print(f"  - {bl['Name']} ({bl['ResponseTime']}ms)")
    
    # Final URL Check
    print(f"\n{' Final URL Check ':-^60}")
    vt_score = check_virustotal(target)
    if vt_score is not None:
        print(f"VirusTotal URL Score: {vt_score}")
    
    print(f"\n{' Analysis Complete ':=^80}")

if __name__ == "__main__":
    target = input("Enter URL/Domain to analyze: ")
    analyze_url(target)