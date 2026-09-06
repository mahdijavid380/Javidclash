#!/usr/bin/env python3
"""
ترکیب چندین لینک ساب‌اسکریپشن و تولید کانفیگ Clash Meta.
متغیر محیطی SUB_URLS شامل لینک‌ها (هر لینک در یک خط) است.
"""

import os
import sys
import yaml
import json
import base64
import requests
from typing import List, Dict, Any, Optional
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ========== تنظیمات ثابت ==========
BASE_CONFIG = {
    "port": 7890,
    "socks-port": 7891,
    "allow-lan": True,
    "mode": "Rule",
    "log-level": "info",
    "external-controller": "0.0.0.0:9090",
    "dns": {
        "enabled": True,
        "ipv6": True,
        "default-nameserver": ["223.5.5.5", "1.1.1.1"],
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "nameserver": [
            "https://dns.alidns.com/dns-query",
            "https://1.1.1.1/dns-query"
        ]
    }
}

RULES = [
    "DOMAIN-SUFFIX,ir,DIRECT",
    "DOMAIN-KEYWORD,sheypoor,DIRECT",
    "DOMAIN-KEYWORD,divar,DIRECT",
    "DOMAIN-SUFFIX,digikala.com,DIRECT",
    "DOMAIN-SUFFIX,aparat.com,DIRECT",
    "DOMAIN-SUFFIX,irancell.ir,DIRECT",
    "DOMAIN-SUFFIX,mci.ir,DIRECT",
    "DOMAIN-SUFFIX,shaparak.ir,DIRECT",
    "DOMAIN-SUFFIX,sep.ir,DIRECT",
    "DOMAIN-SUFFIX,bmi.ir,DIRECT",
    "DOMAIN-SUFFIX,bpm.bankmellat.ir,DIRECT",
    "DOMAIN-SUFFIX,santander.ir,DIRECT",
    "DOMAIN-KEYWORD,bank,DIRECT",
    "GEOIP,IR,DIRECT,no-resolve",
    "MATCH,🔰 انتخاب پروکسی"
]

# ========== توابع ==========

def parse_content(content: str) -> Optional[Dict[str, Any]]:
    """تلاش برای parse محتوا به دیکشنری."""
    # YAML (با پشتیبانی از چند سند)
    try:
        docs = list(yaml.safe_load_all(content))
        merged = {}
        for doc in docs:
            if isinstance(doc, dict):
                merged.update(doc)
        if merged:
            return merged
    except yaml.YAMLError as e:
        logger.debug(f"YAML parsing failed: {e}")

    # JSON
    try:
        data = json.loads(content)
        if isinstance(data, dict):
            return data
        elif isinstance(data, list):
            return {"proxies": data}
    except json.JSONDecodeError as e:
        logger.debug(f"JSON parsing failed: {e}")

    return None


def fetch_subscription(url: str) -> Optional[Dict[str, Any]]:
    """دریافت محتوا از لینک ساب."""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "application/yaml, application/json, text/plain, */*"
    }
    try:
        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        content = resp.text

        if not content or not content.strip():
            logger.warning(f"محتوای خالی از {url} دریافت شد.")
            return None

        # ذخیره محتوای خام برای دیباگ (در صورت نیاز)
        debug_dir = "debug"
        os.makedirs(debug_dir, exist_ok=True)
        filename = f"{debug_dir}/raw_content_{url.replace('/', '_')[:50]}.txt"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(content)
        logger.info(f"محتوای خام در {filename} ذخیره شد (برای بررسی دستی).")

        # لاگ نمونه محتوا (100 کاراکتر اول)
        sample = content[:100].replace('\n', ' ').replace('\r', '')
        logger.info(f"نمونه محتوا از {url}: {sample}...")

        # تلاش برای parse با محتوای اصلی
        result = parse_content(content)
        if result:
            return result

        # تلاش با decode base64
        try:
            decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
            result = parse_content(decoded)
            if result:
                logger.info("محتوای base64 decode شد و pars شد.")
                return result
        except Exception as e:
            logger.debug(f"Base64 decode failed: {e}")

        # اگر با vmess:// یا vless:// شروع شد، به عنوان لیست URL
        if any(content.startswith(prefix) for prefix in ('vmess://', 'vless://', 'trojan://', 'ss://')):
            logger.warning("محتوای شامل URLهای پروکسی است، اما اسکریپت فعلاً آن‌ها را پشتیبانی نمی‌کند.")
            return None

        # اگر محتوا شبیه HTML است
        if content.strip().startswith('<!DOCTYPE') or content.strip().startswith('<html'):
            logger.error("محتوای دریافتی یک صفحه HTML است (احتمالاً خطا یا ریدایرکت).")
            return None

        logger.error(f"فرمت محتوای {url} قابل تشخیص نیست. لطفاً فایل {filename} را بررسی کنید.")
        return None

    except requests.exceptions.RequestException as e:
        logger.error(f"خطا در درخواست به {url}: {e}")
        return None


def get_proxies(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    proxies = data.get('proxies')
    if isinstance(proxies, list):
        return proxies
    return []


def generate_proxy_key(proxy: Dict[str, Any]) -> str:
    server = proxy.get('server', '')
    port = proxy.get('port', '')
    uuid = proxy.get('uuid', '')
    network = proxy.get('network', '')
    tls = proxy.get('tls', False)
    ws_opts = proxy.get('ws-opts', {})
    path = ws_opts.get('path', '')
    host_header = ws_opts.get('headers', {}).get('Host', '')
    return f"{server}:{port}:{uuid}:{network}:{tls}:{path}:{host_header}"


def merge_proxies(proxies_list: List[List[Dict]]) -> List[Dict]:
    seen = set()
    merged = []
    for proxies in proxies_list:
        for p in proxies:
            key = generate_proxy_key(p)
            if key not in seen:
                seen.add(key)
                merged.append(p)
    return merged


def build_proxy_groups(all_proxies: List[Dict]) -> List[Dict]:
    proxy_names = [p.get('name') for p in all_proxies if p.get('name')]

    select_group = {
        "name": "🔰 انتخاب پروکسی",
        "type": "select",
        "proxies": ["♻️ خودکار", "DIRECT"] + proxy_names
    }

    auto_group = {
        "name": "♻️ خودکار",
        "type": "url-test",
        "url": "http://www.gstatic.com/generate_204",
        "interval": 300,
        "tolerance": 50,
        "proxies": proxy_names
    }

    iran_group = {
        "name": "🇮🇷 سرویس‌های ایرانی",
        "type": "select",
        "proxies": ["DIRECT", "🔰 انتخاب پروکسی"]
    }

    return [select_group, auto_group, iran_group]


def main():
    sub_urls_str = os.environ.get('SUB_URLS', '')
    if not sub_urls_str:
        logger.error("متغیر محیطی SUB_URLS تنظیم نشده است.")
        sys.exit(1)

    urls = [u.strip() for u in sub_urls_str.split('\n') if u.strip()]
    if not urls:
        logger.error("هیچ لینک سابی در SUB_URLS یافت نشد.")
        sys.exit(1)

    logger.info(f"دریافت از {len(urls)} لینک ...")

    all_proxies_list = []
    for url in urls:
        data = fetch_subscription(url)
        if data:
            proxies = get_proxies(data)
            if proxies:
                logger.info(f"تعداد {len(proxies)} پروکسی از {url} دریافت شد.")
                all_proxies_list.append(proxies)
            else:
                logger.warning(f"هیچ پروکسی در {url} یافت نشد. کلیدهای موجود: {list(data.keys())}")
        else:
            logger.warning(f"دریافت داده از {url} ناموفق بود.")

    if not all_proxies_list:
        logger.error("هیچ پروکسی از هیچ سابی دریافت نشد.")
        sys.exit(1)

    merged_proxies = merge_proxies(all_proxies_list)
    logger.info(f"تعداد پروکسی‌های یکتا: {len(merged_proxies)}")

    proxy_groups = build_proxy_groups(merged_proxies)
    config = BASE_CONFIG.copy()
    config['proxies'] = merged_proxies
    config['proxy-groups'] = proxy_groups
    config['rules'] = RULES

    os.makedirs('output', exist_ok=True)
    output_path = 'output/config.yaml'
    with open(output_path, 'w', encoding='utf-8') as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False, default_flow_style=False)

    logger.info(f"کانفیگ نهایی در {output_path} ذخیره شد.")


if __name__ == "__main__":
    main()
