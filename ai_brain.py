import json
import time  # NEW: We need this to make the script wait
from google import genai

print(r"""
   _____                 __       ___    ____ 
  / ___/___  ____  _____/ /_     /   |  /  _/ 
  \__ \/ _ \/ __ \/ ___/ __ \   / /| |  / /   
 ___/ /  __/ / / / /__/ / / /  / ___   / /    
/____/\___/_/ /_/\___/_/ /_/  /_/  |_/___/    
""")

# 1. Setup the API Key
API_KEY = input("[*] Enter your Gemini API Key: ")

# 2. Initialize the AI Client
print("\n[*] Booting up the Agent's AI Client...")
client = genai.Client(api_key=API_KEY)

# 3. Load the memory
print("[*] Loading recon_data.json into memory...")
try:
    with open("recon_data.json", "r") as f:
        recon_data = json.load(f)
except FileNotFoundError:
    print("[-] Error: recon_data.json not found. Run recon_sensor.py first!")
    exit()

# 4. Craft the Prompt
prompt = f"""
You are an expert cybersecurity penetration tester and bug bounty hunter.
I am providing you with reconnaissance data in JSON format containing subdomains, IP addresses, and HTTP/HTTPS status codes.

Analyze this data and identify the top 3 most "interesting" targets for potential vulnerabilities (like subdomain takeovers, forgotten staging environments, or exposed admin panels). 
Explain exactly why you chose them from a hacker's perspective.

Data:
{json.dumps(recon_data, indent=2)}
"""

# 5. Execute the Analysis (With Retry Loop)
print("[*] Feeding data to the AI. Awaiting analysis report...")

max_retries = 3
base_delay = 5  # Base wait time in seconds

for attempt in range(1, max_retries + 1):
    try:
        # The AI Generation Call
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt,
        )
        
        # If successful, print and break out of the loop
        print("\n================ AI ANALYSIS REPORT ================\n")
        print(response.text)
        print("\n====================================================")
        break  
        
    except Exception as e:
        print(f"\n[-] Attempt {attempt}/{max_retries} failed: Server Error (503).")
        
        if attempt < max_retries:
            # Calculate wait time: 5s, then 10s
            sleep_time = base_delay * attempt 
            print(f"[*] Agent backing off. Retrying in {sleep_time} seconds...")
            time.sleep(sleep_time)
        else:
            print("[-] Critical Failure: AI servers are completely unreachable right now. Try again later.")