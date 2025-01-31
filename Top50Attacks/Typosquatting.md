# Typosquatting Attack Analysis

## Rule of Thumb to Identify Typosquatting Attacks

Typosquatting involves registering domain names that are similar to legitimate domains, often with slight misspellings or variations. Here are some indicators to look for:

1. **Misspelled Domains**: Look for domains that are similar to legitimate ones but with common misspellings (e.g., `gooogle.com` instead of `google.com`).
2. **Homoglyphs**: Domains that use characters that look similar to the original ones (e.g., `g00gle.com` instead of `google.com`).
3. **Additional or Missing Characters**: Domains with extra or missing characters (e.g., `gogle.com` or `googl.com`).
4. **Different TLDs**: Domains that use different top-level domains (TLDs) (e.g., `google.net` instead of `google.com`).
5. **Subdomains**: Look for suspicious subdomains that mimic legitimate ones (e.g., `login.google.com.example.com`).

## Analyzing Typosquatting Attacks Using SPL (Search Processing Language)

To analyze typosquatting attacks using SPL in Splunk, you can use the following queries:

### Example 1: Identifying Misspelled Domains
```bash
index=web_traffic
| eval domain=mvindex(split(url, "/"), 2)
| search domain="*gooogle.com" OR domain="*g00gle.com" OR domain="*gogle.com" OR domain="*googl.com"
| stats count by domain
```

### Example 2: Detecting Homoglyphs and Variations
```bash
index=web_traffic
| eval domain=mvindex(split(url, "/"), 2)
| regex domain="(g[o0]{2}gle\.com|g[o0]ogle\.com|googl[e3]\.com)"
| stats count by domain
```

### Example 3: Monitoring Different TLDs
```bash
index=web_traffic
| eval domain=mvindex(split(url, "/"), 2)
| search domain="*google.net" OR domain="*google.org" OR domain="*google.co"
| stats count by domain
```

### Example 4: Identifying Suspicious Subdomains
```bash
index=web_traffic
| eval domain=mvindex(split(url, "/"), 2)
| regex domain="(login\.google\.com\..*|account\.google\.com\..*)"
| stats count by domain
```

By using these SPL queries, you can identify potential typosquatting attacks and take appropriate actions to mitigate them.
