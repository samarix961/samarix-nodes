#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
V2Ray / VLess / Trojan / Shadowsocks config fetcher & health checker

خروجی‌ها:
  - sub.txt      : فیلتر نرم (همه‌ی کانفیگ‌های Alive، برای استفاده عمومی/آرشیو)
  - samarix.txt  : فیلتر سخت‌گیرانه (بین‌المللی، محدود به کشور/پورت برای برنامه‌ی اصلی)

طراحی‌شده برای اجرا در GitHub Actions
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
import random
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

# ---------------- تنظیم محیط ----------------

IS_GITHUB_ACTIONS = os.getenv("GITHUB_ACTIONS") == "true"

CONFIG = {
    "soft_file": "sub.txt",        # خروجی فیلتر نرم
    "hard_file": "samarix.txt",    # خروجی فیلتر سخت

    # شبکه
    "request_timeout": 15,
    "request_delay_min": 0.8,
    "request_delay_max": 2.0,

    # تست‌ها
    "test_timeout": 3,
    "tcp_retry": 2,
    "max_workers": 20 if IS_GITHUB_ACTIONS else 50,

    # حداقل تعداد کانفیگ سالم برای این‌که sub.txt را آپدیت کنیم
    "min_soft_configs": 10,
}

COUNTRIES = [
    "us", "gb", "jp", "sg", "de", "nl", "ca", "fr", "kr", "hk",
    "tw", "au", "se", "ch", "no", "in", "br", "tr", "ru", "es",
    "pl", "cz", "at", "ae", "ro", "za", "il", "my", "ar"
]

# کشورهای اولویت بالا (۳ تا در samarix برای پورت‌های مشکوک)
HIGH_PRIORITY = {
    "US", "GB", "DE", "NL", "CA", "FR", "JP", "SG", "KR", "AU", "SE"
}

# پورت‌های خوب (وبی/طبیعی) – بدون محدودیت تعداد در samarix
GOOD_PORTS = {80, 443, 8443, 8080, 2053, 2083, 2087, 2095, 2096}

# پورت‌های حساس پرتکرار (کنترل ویژه)
SENSITIVE_PORTS = {990, 12000}

def log(msg):
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}] {msg}")


# ---------------- پارس کانفیگ ----------------

def parse_config(link: str):
    """استخراج host و port از لینک کانفیگ؛ در صورت شکست (None, None)."""
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
            # ss://...@host:port#name
            if '@' in link:
                part = link.split('@', 1)[1].split('#', 1)[0]
                if ':' in part:
                    host, port = part.rsplit(':', 1)
                    return host, int(port)
    except Exception:
        pass
    return None, None


# ---------------- تست TCP و Ping ----------------

def check_tcp(host, port, timeout):
    """تست TCP روی host:port با چند بار تلاش."""
    for _ in range(CONFIG["tcp_retry"]):
        try:
            sock = socket.create_connection(
                (host, int(port)),
                timeout=timeout
            )
            sock.close()
            return True
        except Exception:
            time.sleep(0.1)
    return False


def check_ping(host):
    """تست Ping (فقط در حالت نرم استفاده می‌شود)."""
    try:
        param = "-n" if platform.system().lower() == "windows" else "-c"
        cmd = ["ping", param, "1", "-W", "2", host]
        return subprocess.call(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        ) == 0
    except Exception:
        return False


def test_single_config(link: str, strict_parse: bool, strict_tcp_only: bool):
    """
    تست یک کانفیگ:
      strict_parse:
        True  -> اگر host/port درنیاید، حذف
        False -> اگر host/port درنیاید، نگه داشتن
      strict_tcp_only:
        True  -> فقط TCP قبول است
        False -> اگر TCP نشد ولی Ping اوکی بود، قبول
    """
    host, port = parse_config(link)

    if not host or not port:
        return link, (not strict_parse)

    if check_tcp(host, port, timeout=CONFIG["test_timeout"]):
        return link, True

    if (not strict_tcp_only) and check_ping(host):
        return link, True

    return link, False


# ---------------- دریافت کانفیگ‌ها ----------------

def get_configs():
    log("🚀 شروع دریافت کانفیگ‌ها از v2nodes ...")
    all_configs = []
    seen = set()

    session = requests.Session()

    # ترتیب کشورها را تصادفی می‌کنیم، اما داخل هر کشور از بالا به پایین می‌خوانیم
    countries = COUNTRIES.copy()
    random.shuffle(countries)

    for country in countries:
        try:
            url = f"https://www.v2nodes.com/country/{country}/"
            resp = session.get(url, timeout=CONFIG["request_timeout"])

            if resp.status_code != 200:
                continue

            m = re.search(
                r"https://www\.v2nodes\.com/subscriptions/country/[a-z0-9\-]+/\?key=[A-Za-z0-9]+",
                resp.text
            )
            if not m:
                continue

            sub_url = m.group(0)
            sub_resp = session.get(sub_url, timeout=CONFIG["request_timeout"])
            content = sub_resp.text.strip()

            try:
                if not any(p in content for p in ("vmess://", "vless://", "trojan://", "ss://")):
                    decoded = base64.b64decode(content).decode("utf-8")
                else:
                    decoded = content
            except Exception:
                decoded = content

            new_count = 0
            for line in decoded.splitlines():
                line = line.strip()
                if not line:
                    continue
                if any(line.startswith(p) for p in ("vmess://", "vless://", "trojan://", "ss://")):
                    if line not in seen:
                        seen.add(line)
                        all_configs.append(line)  # ترتیب سایت حفظ می‌شود
                        new_count += 1

            if new_count > 0:
                log(f"  + {country.upper()}: {new_count} کانفیگ جدید")

        except Exception as e:
            log(f"  - خطا در {country.upper()}: {str(e)[:60]}")

        delay = random.uniform(CONFIG["request_delay_min"], CONFIG["request_delay_max"])
        time.sleep(delay)

    session.close()

    log(f"✅ مجموع کانفیگ‌های یکتا (به‌ترتیب سایت): {len(all_configs)}")
    return all_configs


# ---------------- فیلتر کردن با تنظیمات داده‌شده ----------------

def filter_with_mode(configs, strict_parse: bool, strict_tcp_only: bool, label: str):
    log(f"🔍 شروع تست ({label}) روی {len(configs)} کانفیگ با {CONFIG['max_workers']} ترد ...")

    alive = []
    total = len(configs)

    with ThreadPoolExecutor(max_workers=CONFIG["max_workers"]) as executor:
        futures = [
            executor.submit(test_single_config, c, strict_parse, strict_tcp_only)
            for c in configs
        ]
        done = 0

        for fut in as_completed(futures):
            link, ok = fut.result()
            if ok:
                alive.append(link)

            done += 1
            if done % 50 == 0 or done == total:
                percent = done * 100 / total
                log(f"  ... ({label}) تست {done}/{total} ({percent:.1f}%)")

    if total > 0:
        alive_percent = len(alive) * 100 / total
    else:
        alive_percent = 0.0

    log(f"✅ تست ({label}) تمام شد. سالم: {len(alive)} ({alive_percent:.1f}%)")
    return alive


# ---------------- ابزار کشور و پورت ----------------

def extract_country_code(link: str) -> str:
    """
    تلاش برای استخراج کد کشور (US, DE, ...) از قسمت توضیح آخر لینک:
    مثل: #🇺🇸[www.v2nodes.com] vless-US-11966229
    """
    m = re.search(r'\b(vless|vmess|trojan|ss)-([A-Z]{2})-', link)
    if m:
        return m.group(2)
    return "??"  # کشور نامشخص


def categorize_port(port: int) -> str:
    """
    دسته‌بندی پورت:
      - "good"      : در GOOD_PORTS
      - "sensitive" : در SENSITIVE_PORTS (990, 12000)
      - "risky"     : هر پورت دیگری (به‌طور پیش‌فرض مشکوک)
    """
    if port in GOOD_PORTS:
        return "good"
    if port in SENSITIVE_PORTS:
        return "sensitive"
    return "risky"


# ---------------- ساخت samarix.txt ----------------

def build_samarix(soft_configs):
    """
    فیلتر سخت‌گیرانه برای ساخت samarix.txt

    منطق:
      - GOOD_PORTS:
          * برای همه کشورها بدون محدودیت تعداد (فقط TCP و parse)
      - SENSITIVE_PORTS (990, 12000):
          * فقط برای HIGH_PRIORITY
          * برای each کشور اولویت‌دار: max 3 کانفیگ روی این پورت‌ها
      - سایر پورت‌ها (risky):
          * HIGH_PRIORITY → max 5 کانفیگ
          * others       → max 2 کانفیگ
      - ترتیب: همان ترتیب soft_configs (جدیدترها اول)
    """
    log("🔧 شروع ساخت samarix.txt بر اساس فیلتر کشور/پورت ...")

    selected = []

    # شمارنده برای هر کشور
    country_risky = {}      # تعداد روی پورت‌های risky (غیر GOOD/SENSITIVE)
    country_sensitive = {}  # تعداد روی 990/12000

    for link in soft_configs:
        host, port = parse_config(link)
        if not host or not port:
            continue  # در soft نگه داشتیم، ولی برای hard نمی‌گیریم

        try:
            p = int(port)
        except Exception:
            continue

        cc = extract_country_code(link)
        high = cc in HIGH_PRIORITY

        category = categorize_port(p)

        if category == "good":
            # پورت‌های خوب: برای همه کشورها آزاد
            selected.append(link)
            continue

        if category == "sensitive":
            # 990 و 12000: فقط برای کشورهای مهم
            if not high:
                continue
            used_sens = country_sensitive.get(cc, 0)
            max_sens = 3  # حداکثر 3 کانفیگ حساس برای هر کشور معتبر
            if used_sens >= max_sens:
                continue
            country_sensitive[cc] = used_sens + 1
            selected.append(link)
            continue

        # category == "risky"
        used_risky = country_risky.get(cc, 0)
        max_risky = 5 if high else 2
        if used_risky >= max_risky:
            continue
        country_risky[cc] = used_risky + 1
        selected.append(link)

    log(f"✅ تعداد نهایی کانفیگ‌های samarix: {len(selected)} "
        f"(از soft={len(soft_configs)}؛ کشورهای risky: {len(country_risky)}, "
        f"حساس: {len(country_sensitive)})")

    return selected


# ---------------- ذخیره‌سازی ----------------

def save_list_to_file(configs, path, kind: str):
    with open(path, "w", encoding="utf-8") as f:
        for line in configs:
            f.write(line + "\n")
    log(f"💾 {len(configs)} کانفیگ ({kind}) در فایل {path} ذخیره شد.")


# ---------------- main ----------------

def main():
    # 1) گرفتن لیست خام
    configs = get_configs()
    if not configs:
        log("❌ هیچ کانفیگی دریافت نشد!")
        sys.exit(1)

    # 2) فیلتر نرم (برای sub.txt)
    soft_alive = filter_with_mode(
        configs,
        strict_parse=False,      # نرم: لینک‌های غیرقابل‌پارس را هم نگه می‌داریم
        strict_tcp_only=False,   # نرم: اگر فقط Ping اوکی بود هم قبول
        label="SOFT"
    )

    if len(soft_alive) < CONFIG["min_soft_configs"]:
        log(
            f"❌ تعداد کانفیگ سالم در حالت نرم ({len(soft_alive)}) کمتر از حداقل "
            f"({CONFIG['min_soft_configs']}) است؛ هیچ فایلی آپدیت نمی‌شود."
        )
        sys.exit(1)

    save_list_to_file(soft_alive, CONFIG["soft_file"], "SOFT")

    # 3) ساخت فیلتر سخت (samarix.txt) بر اساس soft_alive
    hard_alive = build_samarix(soft_alive)

    if hard_alive:
        save_list_to_file(hard_alive, CONFIG["hard_file"], "HARD")
    else:
        log("⚠️ هیچ کانفیگی برای samarix انتخاب نشد (احتمالاً فیلتر خیلی محدودکننده بوده).")

    sys.exit(0)


if __name__ == "__main__":
    main()
