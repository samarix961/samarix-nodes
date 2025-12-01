#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
V2Ray / VLess / Trojan / Shadowsocks config fetcher & health checker
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
    "main_file": "sub.txt",

    # شبکه
    "request_timeout": 15,
    "request_delay_min": 0.8,   # حداقل تاخیر بین درخواست‌ها
    "request_delay_max": 2.0,   # حداکثر تاخیر بین درخواست‌ها

    # تست‌ها
    "test_timeout": 3,
    "tcp_retry": 2,
    "max_workers": 20 if IS_GITHUB_ACTIONS else 50,

    # حداقل تعداد کانفیگ سالم برای این‌که فایل را آپدیت کنیم
    "min_configs": 10,
}

# سخت‌گیری تست‌ها (در صورت نیاز می‌توانی بعداً تغییرشان دهی)
STRICT_PARSE = True       # اگر True باشد، لینک‌هایی که host/port ندارند حذف می‌شوند
STRICT_TCP_ONLY = True    # اگر True باشد، فقط TCP ملاک است؛ Ping در قبولی نقشی ندارد

COUNTRIES = [
    "us", "gb", "jp", "sg", "de", "nl", "ca", "fr", "kr", "hk",
    "tw", "au", "se", "ch", "no", "in", "br", "tr", "ru", "es",
    "pl", "cz", "at", "ae", "ro", "za", "il", "my", "ar"
]


# ---------------- لاگ ساده ----------------

def log(msg):
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}] {msg}")


# ---------------- پارس کانفیگ ----------------

def parse_config(link: str):
    """
    تلاش برای استخراج host و port از لینک کانفیگ.
    اگر موفق نشود، (None, None) برمی‌گرداند.
    """
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
            # حالت رایج: ss://xxxx@host:port#name
            if '@' in link:
                part = link.split('@', 1)[1].split('#', 1)[0]
                if ':' in part:
                    host, port = part.rsplit(':', 1)
                    return host, int(port)
    except Exception:
        pass
    return None, None


# ---------------- تست TCP و Ping ----------------

def check_tcp(host, port):
    """
    تست TCP روی host:port با چند بار تلاش.
    """
    for _ in range(CONFIG["tcp_retry"]):
        try:
            sock = socket.create_connection(
                (host, int(port)),
                timeout=CONFIG["test_timeout"]
            )
            sock.close()
            return True
        except Exception:
            time.sleep(0.1)
    return False


def check_ping(host):
    """
    تست Ping (فقط اگر STRICT_TCP_ONLY=False باشد ممکن است برای قبولی استفاده شود).
    در حالت فعلی ما، Ping در تصمیم نهایی نقشی ندارد.
    """
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


def test_single_config(link: str):
    """
    منطق تست هر کانفیگ:
      - اگر پارس نشود:
          * اگر STRICT_PARSE=True -> حذف
          * اگر STRICT_PARSE=False -> نگه داشتن
      - اگر TCP OK -> قبول
      - اگر STRICT_TCP_ONLY=False و Ping OK -> قبول
      - در غیر این صورت -> حذف
    """
    host, port = parse_config(link)

    if not host or not port:
        return link, (not STRICT_PARSE)

    if check_tcp(host, port):
        return link, True

    if not STRICT_TCP_ONLY and check_ping(host):
        return link, True

    return link, False


# ---------------- دریافت کانفیگ‌ها ----------------

def get_configs():
    log("🚀 شروع دریافت کانفیگ‌ها از v2nodes ...")
    all_configs = set()

    # سشن مشترک برای تمام درخواست‌ها
    session = requests.Session()

    # ترتیب کشورها را هر بار به‌طور تصادفی قاطی می‌کنیم
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

            # اگر محتوای subscription مستقیماً لینک‌ها نبود، سعی می‌کنیم base64 دیکد کنیم
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
                    if line not in all_configs:
                        all_configs.add(line)
                        new_count += 1

            if new_count > 0:
                log(f"  + {country.upper()}: {new_count} کانفیگ جدید")

        except Exception as e:
            log(f"  - خطا در {country.upper()}: {str(e)[:60]}")

        # تاخیر تصادفی بین درخواست‌ها برای کاهش الگوی ثابت
        delay = random.uniform(CONFIG["request_delay_min"], CONFIG["request_delay_max"])
        time.sleep(delay)

    session.close()

    log(f"✅ مجموع کانفیگ‌های یکتا: {len(all_configs)}")
    return list(all_configs)


# ---------------- فیلتر کردن Aliveها ----------------

def filter_alive(configs):
    log(f"🔍 شروع تست سلامت {len(configs)} کانفیگ با {CONFIG['max_workers']} ترد ...")

    alive = []
    total = len(configs)

    with ThreadPoolExecutor(max_workers=CONFIG["max_workers"]) as executor:
        futures = [executor.submit(test_single_config, c) for c in configs]
        done = 0

        for fut in as_completed(futures):
            link, ok = fut.result()
            if ok:
                alive.append(link)

            done += 1
            if done % 50 == 0 or done == total:
                percent = done * 100 / total
                log(f"  ... تست {done}/{total} ({percent:.1f}%)")

    if total > 0:
        alive_percent = len(alive) * 100 / total
    else:
        alive_percent = 0.0

    log(f"✅ تست سلامت تمام شد. سالم: {len(alive)} ({alive_percent:.1f}%)")
    return alive


# ---------------- ذخیره‌سازی امن ----------------

def save_if_enough(alive_configs, total_fetched):
    """
    اگر تعداد alive_configs >= min_configs باشد → فایل را overwrite می‌کنیم.
    اگر کمتر باشد → exit code = 1 (در GitHub یعنی fail و commit انجام نمی‌شود).
    """
    alive_count = len(alive_configs)
    if alive_count < CONFIG["min_configs"]:
        log(
            f"❌ تعداد کانفیگ سالم ({alive_count}) کمتر از حداقل مجاز "
            f"({CONFIG['min_configs']}) است؛ فایل قبلی دست‌نخورده می‌ماند."
        )
        return False

    with open(CONFIG["main_file"], "w", encoding="utf-8") as f:
        for line in alive_configs:
            f.write(line + "\n")

    alive_percent = (alive_count * 100 / total_fetched) if total_fetched else 0.0
    log(
        f"💾 {alive_count} کانفیگ سالم در {CONFIG['main_file']} ذخیره شد "
        f"(از {total_fetched}، حدود {alive_percent:.1f}%)."
    )
    return True


# ---------------- main ----------------

def main():
    # 1) دریافت لیست خام
    configs = get_configs()
    if not configs:
        log("❌ هیچ کانفیگی دریافت نشد!")
        sys.exit(1)

    # 2) تست سلامت
    alive_configs = filter_alive(configs)

    # 3) ذخیره فقط اگر به اندازه کافی سالم داشتیم
    ok = save_if_enough(alive_configs, len(configs))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
