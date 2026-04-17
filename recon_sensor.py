import requests
import socket
import json
import sys
import urllib3

# Suppress insecure request warnings for HTTPS probing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

print(r"""
    ____                           ____                             
   / __ \___  _{\___  ___  ____   / __/___  ____  __________  _____
  / /_/ / _ \/ ___/ __ \/ __ \  \__ \/ _ \/ __ \/ ___/ __ \/ ___/
 / _, _/  __/ /__/ /_/ / / / / ___/ /  __/ / / (__  ) /_/ / /    
/_/ |_|\___/\___/\____/_/ /_/ /____/\___/_/ /_/____/\____/_/     
""")

# ==========================================
# PHASE 1: PASSIVE RECON (crt.sh)
# ==========================================
def gather_subdomains(domain):
    print(f"[*] Querying crt.sh for subdomains of: {domain}")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subdomains = set()
    
    try:
        # We use a User-Agent to prevent crt.sh from blocking the script
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        response = requests.get(url, headers=headers, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                name_value = entry['name_value']
                # Sometimes crt.sh returns multiple domains separated by newlines
                for sub in name_value.split('\n'):
                    # Ignore wildcard domains like *.example.com
                    if not sub.startswith("*."):
                        subdomains.add(sub.strip().lower())
        else:
            print(f"[-] crt.sh returned status code: {response.status_code}")
    except Exception as e:
        print(f"[-] Error querying crt.sh: {e}")
        
    return list(subdomains)

# ==========================================
# PHASE 2: ACTIVE VERIFICATION (DNS Resolution)
# ==========================================
def check_alive(subdomains):
    alive = {}
    for sub in subdomains:
        try:
            # If the domain resolves to an IP, it's alive
            ip = socket.gethostbyname(sub)
            alive[sub] = {"ip": ip}
        except socket.gaierror:
            # If it fails to resolve, it's a dead DNS record
            pass
            
    return alive

# ==========================================
# PHASE 3: WEB PROBING (HTTP/HTTPS)
# ==========================================
def probe_web_services(alive_subdomains):
    print("\n[*] Agent initiating HTTP/HTTPS web probing...")
    
    for sub in alive_subdomains:
        http_status = "No Response"
        https_status = "No Response"
        
        # Check HTTP (Port 80)
        try:
            r_http = requests.get(f"http://{sub}", timeout=3)
            http_status = r_http.status_code
        except requests.exceptions.RequestException:
            pass
            
        # Check HTTPS (Port 443) - verify=False ignores bad SSL certificates
        try:
            r_https = requests.get(f"https://{sub}", timeout=3, verify=False)
            https_status = r_https.status_code
        except requests.exceptions.RequestException:
            pass
            
        # Store results in the dictionary
        alive_subdomains[sub]["http"] = http_status
        alive_subdomains[sub]["https"] = https_status
        
        print(f"[+] PROBED: {sub} -> HTTP: {http_status} | HTTPS: {https_status}")
        
    # Save the final structured data to JSON
    print("\n[+] Agent memory saved to recon_data.json")
    with open("recon_data.json", "w") as f:
        json.dump(alive_subdomains, f, indent=4)
        
    return alive_subdomains

# ==========================================
# EXECUTION BLOCK
# ==========================================
if __name__ == "__main__":
    # 1. Check if the user provided a domain in the terminal
    if len(sys.argv) < 2:
        print("[-] Error: Missing target domain.")
        print("[*] Usage: python recon_sensor.py <target_domain>")
        sys.exit(1)
        
    # 2. Grab the domain from the terminal command
    target_domain = sys.argv[1]
    
    # 3. Run Phase 1
    discovered = gather_subdomains(target_domain)
    
    if discovered:
        print(f"\n[*] Found {len(discovered)} total subdomains. Filtering the noise...")
        
        # Run Phase 2
        alive_subdomains = check_alive(discovered)
        print(f"\n[+] Agent confirmed {len(alive_subdomains)} alive targets ready for further analysis.")
        
        # 4. Run Phase 3
        if alive_subdomains:
            probe_web_services(alive_subdomains)
        else:
            print("[-] No alive subdomains found to probe.")
    else:
        print("\n[-] No subdomains found to process.")