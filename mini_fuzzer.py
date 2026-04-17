import requests
import urllib3

# Suppress warnings for clean output
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

print(r"""
    ____        __  __                 
   / __ \__  __/ /_/ /_  ____  ____    
  / /_/ / / / / __/ __ \/ __ \/ __ \   
 / ____/ /_/ / /_/ / / / /_/ / / / /   
/_/    \__, /\__/_/ /_/\____/_/ /_/    
      /____/                           
""")

target_url = "https://api.hackerone.com/"

# Instead of a massive text file, here is a highly targeted "dictionary"
# specifically designed for finding hidden API routes.
api_wordlist = [
    "v1", "v2", "v3", "graphql", "users", "admin", "internal", 
    "debug", "status", "health", "docs", "test", "staging", 
    "swagger", "metrics", "config"
]

print(f"[*] Target: {target_url}")
print(f"[*] Loaded {len(api_wordlist)} payloads. Commencing attack run...\n")

# The Loop (This is what ffuf does under the hood)
for word in api_wordlist:
    test_url = f"{target_url}{word}"
    
    try:
        # Send the GET request
        response = requests.get(test_url, timeout=3, verify=False)
        
        # We ignore 404s (Not Found). We only want to see things that exist
        # like 200 (OK), 403 (Forbidden), or 401 (Unauthorized)
        if response.status_code != 404:
            print(f"[!] HIT: {test_url} -> Status: {response.status_code}")
            
    except requests.exceptions.RequestException:
        pass

print("\n[*] Fuzzing complete.")