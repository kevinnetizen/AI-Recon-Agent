import requests
import socket
import json

def gather_subdomains(domain):
    """Phase 1: Passively queries certificate logs for subdomains."""
    print(f"[*] Agent initiating passive recon on: {domain}")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=45)
        response.raise_for_status() 
        
        subdomains = set()
        data = response.json()
        
        for entry in data:
            name = entry['name_value']
            if '\n' in name:
                for n in name.split('\n'):
                    subdomains.add(n.strip().lower())
            else:
                subdomains.add(name.strip().lower())
                
        clean_subdomains = [sub for sub in subdomains if not sub.startswith('*')]
        return sorted(clean_subdomains)
        
    except Exception as e:
        print(f"[-] Agent encountered an error during passive recon: {e}")
        return []

def check_alive(subdomains):
    """Phase 2: Actively checks if the found subdomains resolve to an IP."""
    print("\n[*] Agent initiating active DNS resolution...")
    alive_targets = {}
    
    for sub in subdomains:
        try:
            ip = socket.gethostbyname(sub)
            alive_targets[sub] = ip
            print(f"[+] ALIVE: {sub} -> {ip}")
        except socket.gaierror:
            pass
            
    return alive_targets

def probe_web_services(alive_targets):
    """Phase 3: Checks for active web servers and saves data for the AI."""
    print("\n[*] Agent initiating HTTP/HTTPS web probing...")
    results = {}
    
    for sub, ip in alive_targets.items():
        target_info = {"ip": ip, "http": "No Response", "https": "No Response"}
        
        # 1. Test standard HTTP (Port 80)
        try:
            r = requests.get(f"http://{sub}", timeout=3)
            target_info["http"] = r.status_code
        except requests.exceptions.RequestException:
            pass 
            
        # 2. Test secure HTTPS (Port 443)
        try:
            r_secure = requests.get(f"https://{sub}", timeout=3)
            target_info["https"] = r_secure.status_code
        except requests.exceptions.RequestException:
            pass
            
        print(f"[+] PROBED: {sub} -> HTTP: {target_info['http']} | HTTPS: {target_info['https']}")
        results[sub] = target_info
        
    # 3. Save the brain's memory to a JSON file
    with open("recon_data.json", "w") as f:
        json.dump(results, f, indent=4)
        
    print("\n[+] Agent memory saved to recon_data.json")
    return results

# ==========================================
# EXECUTION BLOCK
# ==========================================
if __name__ == "__main__":
    target_domain = "cuk.ac.ke" 
    
    discovered = gather_subdomains(target_domain)
    
    if discovered:
        print(f"\n[*] Found {len(discovered)} total subdomains. Filtering the noise...")
        alive_subdomains = check_alive(discovered)
        
        print(f"\n[+] Agent confirmed {len(alive_subdomains)} alive targets ready for further analysis.")
        
        # Run the web probe and save the data
        final_data = probe_web_services(alive_subdomains)
        
    else:
        print("\n[-] No subdomains found to process.")