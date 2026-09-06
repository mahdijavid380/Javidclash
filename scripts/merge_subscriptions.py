#!/usr/bin/env python3
"""
ترکیب چندین لینک ساب‌اسکریپشن (شامل YAML/JSON و لیست URLهای پروکسی)
و تولید کانفیگ Clash Meta با نام‌های یکتا.
"""

import os
import sys
import yaml
import json
import base64
import requests
from urllib.parse import urlparse, parse_qs
from typing import List, Dict, Any, Optional
import logging
import hashlib

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

def generate_unique_name(server: str, port: int, uuid: str, path: str = "", host: str = "") -> str:
    """تولید نام یکتا بر اساس اطلاعات پروکسی."""
    # اگر host موجود باشد، از آن استفاده می‌کنیم (معمولاً نام دامنه معنی‌دار است)
    base = host if host else server
    # حذف کاراکترهای غیرمجاز برای نام
    base = base.replace('.', '-').replace(':', '-')
    # از 8 کاراکتر اول UUID استفاده می‌کنیم
    short_uuid = uuid[:8]
    # اگر مسیر خاصی وجود دارد، آن را هم اضافه می‌کنیم (برای تشخیص بهتر)
    path_suffix = ""
    if path and path != "/":
        # فقط 5 کاراکتر اول مسیر را می‌گیریم
        clean_path = path.strip('/').replace('/', '-')[:5]
        if clean_path:
            path_suffix = f"-{clean_path}"
    # ترکیب نهایی
    name = f"{base}-{port}-{short_uuid}{path_suffix}"
    # اگر نام طولانی شد، کوتاه می‌کنیم (حداکثر 50 کاراکتر)
    if len(name) > 50:
        # هش می‌گیریم و از 8 کاراکتر اول استفاده می‌کنیم
        hash_part = hashlib.md5(name.encode()).hexdigest()[:8]
        name = f"{base[:20]}-{port}-{hash_part}"
    return name


def parse_vless_url(url: str) -> Optional[Dict[str, Any]]:
    """
    Parse یک URL vless:// و تبدیل به دیکشنری پروکسی Clash.
    """
    if not url.startswith('vless://'):
        return None

    try:
        raw = url[8:]
        if '@' not in raw:
            return None
        uuid, rest = raw.split('@', 1)
        if ':' not in rest:
            return None
        server, port_and_params = rest.split(':', 1)
        if '?' not in port_and_params:
            return None
        port_str, query = port_and_params.split('?', 1)
        port = int(port_str)

        params = parse_qs(query)
        def get_first(key):
            return params.get(key, [''])[0] if params.get(key) else ''

        network = get_first('type') or 'ws'
        host = get_first('host')
        path = get_first('path') or '/'
        tls = get_first('tls') == 'true' or get_first('tls') == '1' or get_first('security') == 'tls'
        servername = get_first('servername') or get_first('sni') or host or server
        remark = get_first('remark') or get_first('name') or ""

        # تولید نام یکتا
        name = generate_unique_name(server, port, uuid, path, host)
        # اگر remark وجود داشت، می‌توان از آن استفاده کرد اما باید یکتا بودن را تضمین کنیم
        if remark:
            # برای جلوگیری از تداخل، از ترکیب remark و uuid استفاده می‌کنیم
            name = f"{remark[:30]}-{uuid[:8]}"

        proxy = {
            "type": "vless",
            "name": name,
            "server": server,
            "port": port,
            "uuid": uuid,
            "network": network,
            "tls": tls,
        }

        if servername:
            proxy["servername"] = servername

        if network == 'ws':
            ws_opts = {"path": path}
            if host:
                ws_opts["headers"] = {"Host": host}
            proxy["ws-opts"] = ws_opts

        return proxy

    except Exception as e:
        logger.debug(f"خطا در parse URL {url}: {e}")
        return None


def parse_proxy_urls(content: str) -> List[Dict[str, Any]]:
    """استخراج پروکسی‌ها از لیست URLها (vless://, vmess://, ...)."""
    proxies = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith('vless://'):
            p = parse_vless_url(line)
            if p:
                proxies.append(p)
        # می‌توان برای vmess, trojan, ss هم اضافه کرد
    return proxies


def parse_content(content: str) -> Optional[Dict[str, Any]]:
    """تلاش برای parse محتوا به دیکشنری (YAML/JSON/URL list)."""
    # YAML
    try:
        docs = list(yaml.safe_load_all(content))
        merged = {}
        for doc in docs:
            if isinstance(doc, dict):
                merged.update(doc)
        if merged:
            return merged
    except yaml.YAMLError:
        pass

    # JSON
    try:
        data = json.loads(content)
        if isinstance(data, dict):
            return data
        elif isinstance(data, list):
            return {"proxies": data}
    except json.JSONDecodeError:
        pass

    # لیست URLهای پروکسی
    proxies = parse_proxy_urls(content)
    if proxies:
        return {"proxies": proxies}

    return None


def fetch_subscription(url: str) -> Optional[Dict[str, Any]]:
    """دریافت محتوا از لینک ساب."""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "application/yaml, application/json, text/plain, */*"
    }
    try:
        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        content = resp.text

        if not content or not content.strip():
            logger.warning(f"محتوای خالی از {url} دریافت شد.")
            return None

        # ذخیره محتوای خام برای دیباگ
        debug_dir = "debug"
        os.makedirs(debug_dir, exist_ok=True)
        filename = f"{debug_dir}/raw_{url.replace('/', '_')[:50]}.txt"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(content)
        logger.info(f"محتوای خام در {filename} ذخیره شد.")

        sample = content[:100].replace('\n', ' ').replace('\r', '')
        logger.info(f"نمونه محتوا: {sample}...")

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
        except Exception:
            pass

        logger.error(f"فرمت محتوای {url} قابل تشخیص نیست.")
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
                logger.warning(f"هیچ پروکسی در {url} یافت نشد. کلیدها: {list(data.keys())}")
        else:
            logger.warning(f"دریافت داده از {url} ناموفق بود.")

    if not all_proxies_list:
        logger.error("هیچ پروکسی از هیچ سابی دریافت نشد.")
        sys.exit(1)

    merged_proxies = merge_proxies(all_proxies_list)
    logger.info(f"تعداد پروکسی‌های یکتا: {len(merged_proxies)}")

    # اطمینان از یکتایی نام‌ها (در صورت وجود تکراری، یک عدد به انتها اضافه می‌کنیم)
    name_count = {}
    for proxy in merged_proxies:
        name = proxy['name']
        if name in name_count:
            name_count[name] += 1
            proxy['name'] = f"{name}-{name_count[name]}"
        else:
            name_count[name] = 1

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
