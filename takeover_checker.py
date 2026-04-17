import json
import dns.resolver

print("[*] Booting up Subdomain Takeover Analyzer...")

# Load the memory
try:
    with open("recon_data.json", "r") as f:
        recon_data = json.load(f)
except FileNotFoundError:
    print("[-] Error: recon_data.json not found.")
    exit()

print("[*] Scanning memory for vulnerable 'No Response' targets...\n")

for subdomain, data in recon_data.items():
    if data['http'] == "No Response" and data['https'] == "No Response":
        try:
            # Query the DNS servers specifically for CNAME (Alias) records
            answers = dns.resolver.resolve(subdomain, 'CNAME')
            for rdata in answers:
                target = rdata.target.to_text()
                print(f"[!] POTENTIAL VULNERABILITY FOUND:")
                print(f"    - Subdomain: {subdomain}")
                print(f"    - Points to (CNAME): {target}")
                print(f"    - Status: Check if {target} is an unclaimed cloud service!\n")
        except dns.resolver.NoAnswer:
            # No CNAME exists, likely just a dead A record (less critical)
            pass
        except dns.resolver.NXDOMAIN:
            pass
        except Exception as e:
            pass

print("[+] Analysis complete.")