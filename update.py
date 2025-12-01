#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
V2Ray Config Fetcher & Health Checker
بهینه شده برای GitHub Actions
"""

import os
import sys
import re
import time
import json
import base64
import socket
import subprocess
import platform
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

# تشخیص محیط (جهت تنظیم تردها)
IS_GITHUB_ACTIONS = os.getenv("GITHUB_ACTIONS") == "true"

# =============== تنظیمات ===============
CONFIG = {
    "main_file": "sub.txt",
    
    # تنظیمات شبکه
    "request_timeout": 15,
    "request_delay": 0.5,
    
    # تنظیمات تست
    "test_timeout": 3,
    "tcp_retry": 2,
    
    # تعداد تردها (در گیت‌هاب کمتر باشد تا فشار نیاید)
    "max_workers": 20 if IS_GITHUB_ACTIONS else 50,
    
    # امنیت: حداقل تعداد کانفیگ سالم برای آپدیت فایل
    "min_configs": 10,
}

# لیست کشورها
COUNTRIES = [
    "us", "gb", "jp", "sg", "de", "nl", "ca", "fr", "kr", "hk",
    "tw", "au", "se", "ch", "no", "in", "br", "tr", "ru", "es",
    "pl", "cz", "at", "ae", "ro", "za", "il", "my", "ar"
]

# --- لاگ ساده و خوانا ---
def log(msg):
    timestamp = time.strftime("%H:%M:%S")
    print(f"[{timestamp}] {msg}")

# --- توابع پارس ---
def parse_config(link: str):
    try:
        if link.startswith("vmess://"):
            b64 = link[8:]
            b64 += "=" * ((4 - len(b64) % 4) % 4)
            data = json.loads(base64.b64decode(b64).decode("utf-8"))
            return data.get("add"), data.get("port")

        if link.startswith(("vless://", "trojan://")):
            parsed = urlparse(link)
            return parsed.hostname, parsed.port

        if link.startswith("ss://"):
            if '@' in link:
                part = link.split('@', 1)[1].split('#', 1)[0]
                if ':' in part:
                    host, port = part.rsplit(':', 1)
                    return host, int(port)
    except:
        pass
    return None, None

# --- توابع تست سلامت ---
def check_tcp(host, port):
    for _ in range(CONFIG["tcp_retry"]):
        try:
            sock = socket.create_connection((host, int(port)), timeout=CONFIG["test_timeout"])
            sock.close()
            return True
        except:
            time.sleep(0.1)
    return False

def check_ping(host):
    try:
        param = "-n" if platform.system().lower() == "windows" else "-c"
        cmd = ["ping", param, "1", "-W", "2", host]
        return subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
    except:
        return False

def test_single_config(link: str):
    host, port = parse_config(link)
    
    # اگر آدرس پیدا نشد، ریسک نمی‌کنیم و نگهش می‌داریم
    if not host or not port:
        return link, True

    # اولویت با TCP
    if check_tcp(host, port):
        return link, True

    # فال‌بک با Ping
    if check_ping(host):
        return link, True

    return link, False

# --- هسته اصلی دریافت ---
def get_configs():
    log("🚀 شروع دریافت کانفیگ‌ها...")
    all_configs = set()
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    for country in COUNTRIES:
        try:
            url = f"https://www.v2nodes.com/country/{country}/"
            resp = requests.get(url, headers=headers, timeout=CONFIG["request_timeout"])

            if resp.status_code != 200:
                continue

            m = re.search(r"https://www\.v2nodes\.com/subscriptions/country/[a-z0-9\-]+/\?key=[A-Za-z0-9]+", resp.text)
            if not m:
                continue

            sub_url = m.group(0)
            content = requests.get(sub_url, headers=headers, timeout=CONFIG["request_timeout"]).text.strip()

            try:
                if not any(p in content for p in ["vmess://", "vless://", "trojan://", "ss://"]):
                    decoded = base64.b64decode(content).decode("utf-8")
                else:
                    decoded = content
            except:
                decoded = content

            count = 0
            for line in decoded.splitlines():
                line = line.strip()
                if line and any(line.startswith(p) for p in ("vmess://", "vless://", "trojan://", "ss://")):
                    if line not in all_configs:
                        all_configs.add(line)
                        count += 1
            
            if count > 0:
                print(f"  + {country.upper()}: {count}")

        except Exception as e:
            print(f"  - خطا در {country.upper()}: {str(e)[:50]}")

        time.sleep(CONFIG["request_delay"])

    log(f"✅ مجموع دریافت شده: {len(all_configs)}")
    return list(all_configs)

# --- اجرای تست موازی ---
def filter_alive(configs):
    log(f"🔍 شروع تست سلامت با {CONFIG['max_workers']} ترد...")
    alive = []
    
    with ThreadPoolExecutor(max_workers=CONFIG["max_workers"]) as executor:
        futures = [executor.submit(test_single_config, c) for c in configs]
        done = 0
        for fut in as_completed(futures):
            link, is_alive = fut.result()
            if is_alive:
                alive.append(link)
            done += 1
            if done % 50 == 0:
                print(f"  ... تست {done}/{len(configs)} انجام شد")

    log(f"✅ پایان تست. سالم: {len(alive)} (از {len(configs)})")
    return alive

# --- برنامه اصلی ---
def main():
    # 1. دریافت
    configs = get_configs()
    if not configs:
        log("❌ هیچ کانفیگی دریافت نشد!")
        sys.exit(1) # خروج با خطا -> ورک‌فلو متوقف می‌شود -> فایل قبلی دست‌نخورده می‌ماند

    # 2. تست
    alive_configs = filter_alive(configs)

    # 3. بررسی کیفیت و ذخیره
    if len(alive_configs) < CONFIG["min_configs"]:
        log(f"❌ تعداد کانفیگ سالم ({len(alive_configs)}) کمتر از حد مجاز ({CONFIG['min_configs']}) است.")
        log("⚠️ آپدیت لغو شد تا فایل قبلی خراب نشود.")
        sys.exit(1) # خروج با خطا

    # اگر همه چیز خوب بود، ذخیره می‌کنیم
    with open(CONFIG["main_file"], "w", encoding="utf-8") as f:
        for line in alive_configs:
            f.write(line + "\n")
    
    log(f"💾 فایل {CONFIG['main_file']} با موفقیت آپدیت شد.")
    sys.exit(0) # خروج موفق

if __name__ == "__main__":
    main()
