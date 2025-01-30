#!/usr/bin/env python3

'''
@Author: Saksham Trivedi
@alias: SK
@Description: This script checks a given URL for malicious indicators using VirusTotal, WHOIS Lookup, and AbuseIPDB APIs.
@Requirements: pip install python-whois whois requests
'''

import requests
import whois
import socket
import json
import base64

# Put your API keys
VIRUSTOTAL_API_KEY = " "
ABUSEIPDB_API_KEY = " "

def check_virustotal(url):
    
    # Check if a URL is flagged as malicious on VirusTotal.

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    
    ## Handling the error if the URL is not encoded properly because the url must be encoded in base64 format.
    try:
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{encoded_url}", headers=headers)
    
        if response.status_code == 200:
            result = response.json()
            malicious_votes = result["data"]["attributes"]["last_analysis_stats"]["malicious"]
            if malicious_votes > 0:
                print(f"[⚠] VirusTotal: {malicious_votes} security vendors flagged this URL!")
            else:
                print("[✔] VirusTotal: No detections found.")
        else:
            print("[!] VirusTotal lookup failed with status code:", response.status_code)
    
    except Exception as e:
        print("[!] VirusTotal lookup failed:", str(e))

def check_whois(domain):

    # Fetch WHOIS information.
    
    try:
        w = whois.whois(domain)
        print(f"[+] WHOIS Info for {domain}:")
        print(f"    - Registrar: {w.registrar}")
        print(f"    - Creation Date: {w.creation_date}")
        print(f"    - Expiry Date: {w.expiration_date}")
    
    except Exception as e:
        print("[!] WHOIS lookup failed:", str(e))

def check_abuseipdb(ip):

    # Check if an IP is reported in AbuseIPDB.
    
    url = "https://api.abuseipdb.com/api/v2/check"
    
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    
    params = {"ipAddress": ip}
    
    try:
    
        response = requests.get(url, headers=headers, params=params)
    
        if response.status_code == 200:
            result = response.json()
            reports = result["data"]["totalReports"]
            if reports > 0:
                print(f"[⚠] AbuseIPDB: {ip} has {reports} reports of abuse!")
            else:
                print("[✔] AbuseIPDB: No abuse reports found.")
        else:
            print("[!] AbuseIPDB lookup failed with status code:", response.status_code)
    
    except Exception as e:
        print("[!] AbuseIPDB lookup failed:", str(e))

def resolve_dns(url):

    # Resolve a domain to an IP address.
    
    try:
        ip = socket.gethostbyname(url)
        print(f"[+] DNS Resolution: {url} → {ip}")
        return ip
    
    except socket.gaierror:
        print("[!] Failed to resolve domain.")
        return None

def analyze_url(url):
    # Main function to analyze a given URL.
    print(f"\n[*] Analyzing URL: {url}")
    
    # Extract domain from URL
    domain = url.split("/")[2] if "http" in url else url

    # Check WHOIS data
    check_whois(domain)

    # Resolve IP and check AbuseIPDB
    ip = resolve_dns(domain)
    if ip:
        check_abuseipdb(ip)

    # Check VirusTotal
    check_virustotal(url)

# Example Usage
malicious_url = input("Enter a URL to analyze: ")
analyze_url(malicious_url)