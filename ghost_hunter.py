import json
import dns.resolver
import sys

print(r"""
   ______ __                 __     __  __               __           
  / ____// /_   ____   _____ / /_   / / / /__  __ ____   / /_ ___   _____
 / / __ / __ \ / __ \ / ___// __/  / /_/ // / / // __ \ / __// _ \ / ___/
/ /_/ // / / // /_/ /(__  )/ /_   / __  // /_/ // / / // /_ /  __// /    
\____//_/ /_/ \____//____/ \__/  /_/ /_/ \__,_//_/ /_/ \__/ \___//_/     
""")

# ==========================================
# CLOUD PROVIDER FINGERPRINTS
# ==========================================
# If a CNAME points to one of these, and returns a 404, it's highly vulnerable.
VULNERABLE_PROVIDERS = {
    "AWS CloudFront": "cloudfront.net",
    "AWS S3 Bucket": "s3.amazonaws.com",
    "Heroku App": "herokuapp.com",
    "GitHub Pages": "github.io",
    "Azure Web App": "azurewebsites.net",
    "Shopify": "myshopify.com",
    "Tumblr": "domains.tumblr.com",
    "WordPress": "wordpress.com",
    "Pantheon": "pantheonsite.io"
}

def load_recon_data(filepath="recon_data.json"):
    try:
        with open(filepath, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"[-] Error: {filepath} not found. Run recon_sensor.py first.")
        sys.exit(1)

def scan_for_takeovers(data):
    print("[*] Analyzing recon data for potential Subdomain Takeovers...\n")
    found_vulnerabilities = 0

    for subdomain, details in data.items():
        # We only care about targets throwing 404s (Ghost Assets)
        if details.get('http') == 404 or details.get('https') == 404:
            try:
                # Ask the DNS server for the CNAME record
                answers = dns.resolver.resolve(subdomain, 'CNAME')
                for rdata in answers:
                    cname_target = rdata.target.to_text().rstrip('.')
                    
                    # Check if the CNAME matches our fingerprint database
                    for provider_name, provider_domain in VULNERABLE_PROVIDERS.items():
                        if provider_domain in cname_target:
                            print(f"[!!!] CRITICAL: Subdomain Takeover Vulnerability Found!")
                            print(f"      - Target: {subdomain}")
                            print(f"      - Points to: {cname_target}")
                            print(f"      - Provider: {provider_name}")
                            print(f"      - Action: Register this asset on {provider_name} to hijack traffic.\n")
                            found_vulnerabilities += 1
                            break # Move to the next subdomain
                            
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                # No CNAME found, it's just a regular 404 on a dedicated server
                pass
            except Exception as e:
                # Catch timeout errors or other DNS glitches cleanly
                pass

    if found_vulnerabilities == 0:
        print("[+] Scan complete. No dangling CNAMEs matching known providers were found.")
    else:
        print(f"[*] Scan complete. Found {found_vulnerabilities} vulnerable targets.")

# ==========================================
# EXECUTION BLOCK
# ==========================================
if __name__ == "__main__":
    # Make sure we have the dnspython library installed
    try:
        import dns.resolver
    except ImportError:
        print("[-] Missing required library. Run: pip install dnspython")
        sys.exit(1)

    recon_data = load_recon_data()
    scan_for_takeovers(recon_data)