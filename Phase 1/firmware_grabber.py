import requests

# Corrected domain endpoint leaked directly from your raw network trace file
BASE_URL = "https://cppluscloud.com"
PRODUCT_KEY = "ZJJlWeje" 
# Testing common Tuya protocol firmware build indices
VERSIONS = ["1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6", "3.3", "4.1"]

print("[+] Probing verified CP PLUS India cloud gateway for firmware binaries...")

for version in VERSIONS:
    filename = f"{PRODUCT_KEY}_{version}.bin"
    target_url = f"{BASE_URL}{filename}" # Verified forward-slash placement
    
    try:
        response = requests.head(target_url, timeout=5)
        if response.status_code == 200:
            print(f"\n[SUCCESS] Firmware found! Target URL: {target_url}")
            print(f"[+] Downloading file: {filename}...")
            
            file_data = requests.get(target_url)
            with open(filename, "wb") as f:
                f.write(file_data.content)
            print("[+] Download complete. File saved to your local directory.")
            break
        else:
            print(f"[-] Checked version {version} ({filename}) -> Status 404 (Not Found)")
    except Exception as e:
        print(f"[-] Network connection error: {e}")
