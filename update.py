import requests
import re
import base64
import os

# لیست کامل کشورها (قدیمی + جدید)
COUNTRIES = [
    "us", "gb", "jp", "sg", "de", "nl", "ca", "fr", "kr", "hk", 
    "tw", "au", "se", "ch", "no", "in", "br", "tr", "ru", "es", 
    "pl", "cz", "at",
    "ae", "ro", "za", "il", "my", "ar"  # کشورهای جدید اضافه شده
]

def get_configs():
    # استفاده از set برای حذف خودکار تکراری‌ها
    unique_configs = set()
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    for country in COUNTRIES:
        try:
            print(f"Fetching {country}...")
            url = f"https://www.v2nodes.com/country/{country}/"
            resp = requests.get(url, headers=headers, timeout=15)
            
            if resp.status_code != 200:
                print(f"Country {country} not found or blocked (Status: {resp.status_code})")
                continue

            match = re.search(r'https://www\.v2nodes\.com/subscriptions/country/[a-z0-9\-]+/\?key=[A-Za-z0-9]+', resp.text)
            if match:
                sub_url = match.group(0)
                sub_resp = requests.get(sub_url, headers=headers, timeout=15)
                content = sub_resp.text.strip()
                
                try:
                    if "vmess://" not in content and "vless://" not in content:
                        decoded = base64.b64decode(content).decode('utf-8')
                    else:
                        decoded = content
                except:
                    decoded = content

                lines = decoded.splitlines()
                for line in lines:
                    line = line.strip()
                    if line and (line.startswith("vmess://") or line.startswith("vless://") or line.startswith("trojan://") or line.startswith("ss://")):
                        unique_configs.add(line)
            else:
                print(f"No subscription link found for {country}")
                            
        except Exception as e:
            print(f"Error fetching {country}: {e}")

    return list(unique_configs)

def save_to_file(configs):
    with open("sub.txt", "w", encoding="utf-8") as f:
        for conf in configs:
            f.write(conf + "\n")

if __name__ == "__main__":
    configs = get_configs()
    print(f"Total unique configs found: {len(configs)}")
    if len(configs) > 0:
        save_to_file(configs)
    else:
        print("No configs found!")
