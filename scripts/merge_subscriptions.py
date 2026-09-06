#!/usr/bin/env python3
"""
ترکیب چندین لینک ساب‌اسکریپشن و تولید کانفیگ Clash Meta.
متغیر محیطی SUB_URLS شامل لینک‌ها (هر لینک در یک خط) است.
"""

import os
import sys
import yaml
import requests
from typing import List, Dict, Any, Set
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ========== تنظیمات ثابت (بر اساس فایل نمونه) ==========
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

# قوانین مسیریابی (بر اساس نمونه)
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

# ========== توابع کمکی ==========

def fetch_subscription(url: str) -> Dict[str, Any]:
    """دریافت و parse محتوای ساب (فرمت YAML)."""
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        content = resp.text

        # تلاش برای بارگذاری YAML
        try:
            # ابتدا safe_load را امتحان می‌کنیم
            data = yaml.safe_load(content)
            if isinstance(data, dict):
                return data
            else:
                # اگر دیکشنری نبود، احتمالاً چندین سند با --- وجود دارد
                docs = list(yaml.safe_load_all(content))
                merged = {}
                for doc in docs:
                    if isinstance(doc, dict):
                        merged.update(doc)
                return merged
        except yaml.YAMLError as e:
            logger.error(f"خطا در پردازش YAML از {url}: {e}")
            return {}
    except Exception as e:
        logger.error(f"خطا در دریافت {url}: {e}")
        return {}


def get_proxies(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """استخراج لیست پروکسی‌ها از دیکشنری ساب."""
    proxies = data.get('proxies')
    if isinstance(proxies, list):
        return proxies
    return []


def generate_proxy_key(proxy: Dict[str, Any]) -> str:
    """ساخت کلید یکتا برای تشخیص پروکسی‌های تکراری."""
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
    """ادغام لیست‌های پروکسی و حذف موارد تکراری."""
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
    """ساخت گروه‌های پروکسی بر اساس لیست پروکسی‌های نهایی."""
    proxy_names = [p.get('name') for p in all_proxies if p.get('name')]

    # گروه انتخاب دستی
    select_group = {
        "name": "🔰 انتخاب پروکسی",
        "type": "select",
        "proxies": ["♻️ خودکار", "DIRECT"] + proxy_names
    }

    # گروه خودکار (url-test)
    auto_group = {
        "name": "♻️ خودکار",
        "type": "url-test",
        "url": "http://www.gstatic.com/generate_204",
        "interval": 300,
        "tolerance": 50,
        "proxies": proxy_names
    }

    # گروه مخصوص سرویس‌های ایرانی
    iran_group = {
        "name": "🇮🇷 سرویس‌های ایرانی",
        "type": "select",
        "proxies": ["DIRECT", "🔰 انتخاب پروکسی"]
    }

    return [select_group, auto_group, iran_group]


def main():
    # خواندن لینک‌ها از متغیر محیطی
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
                logger.warning(f"هیچ پروکسی در {url} یافت نشد.")
        else:
            logger.warning(f"دریافت داده از {url} ناموفق بود.")

    if not all_proxies_list:
        logger.error("هیچ پروکسی از هیچ سابی دریافت نشد.")
        sys.exit(1)

    merged_proxies = merge_proxies(all_proxies_list)
    logger.info(f"تعداد پروکسی‌های یکتا: {len(merged_proxies)}")

    # ساخت گروه‌ها و کانفیگ نهایی
    proxy_groups = build_proxy_groups(merged_proxies)
    config = BASE_CONFIG.copy()
    config['proxies'] = merged_proxies
    config['proxy-groups'] = proxy_groups
    config['rules'] = RULES

    # ذخیره فایل خروجی
    os.makedirs('output', exist_ok=True)
    output_path = 'output/config.yaml'
    with open(output_path, 'w', encoding='utf-8') as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False, default_flow_style=False)

    logger.info(f"کانفیگ نهایی در {output_path} ذخیره شد.")


if __name__ == "__main__":
    main()
