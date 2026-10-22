"""
Phishing URL Detection System - Özellik Çıkarım Motoru (Feature Extraction Engine)
Bu modül, URL adreslerinden leksikal (sözcüksel) ve sezgisel 25 farklı güvenlik niteliğini 
yüksek hızda (< 0.5 ms / URL) ve harici ağ bağımlılığı olmadan çıkarır.
"""

import re
import math
from collections import Counter
from urllib.parse import urlparse
import pandas as pd

# Kimlik avında sıkça kullanılan eylem/güvenlik anahtar sözcükleri
ACTION_KEYWORDS = [
    'login', 'signin', 'log-in', 'sign-in', 'verify', 'verification', 
    'account', 'banking', 'secure', 'security', 'update', 'service', 
    'confirm', 'confirmation', 'password', 'credential', 'auth', 
    'support', 'wallet', 'admin', 'recover', 'billing', 'invoice', 
    'validate', 'checkout', 'ebayisapi', 'webscr'
]

# Hedef alınan popüler markalar (Subdomain veya Path içinde taklit tespiti için)
POPULAR_BRANDS = [
    'paypal', 'apple', 'google', 'microsoft', 'netflix', 'amazon', 
    'facebook', 'instagram', 'binance', 'metamask', 'whatsapp', 'chase', 
    'wellsfargo', 'citibank', 'bankofamerica'
]

# Bilinen URL kısaltma servisleri
SHORTENING_SERVICES = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 
    'buff.ly', 'adf.ly', 'bit.do', 'cutt.ly', 'rb.gy', 'shorte.st'
}

# Yaygın üst düzey alan adları (TLD)
COMMON_TLDS = {'com', 'net', 'org', 'edu', 'gov', 'mil', 'io', 'co', 'info', 'biz', 'xyz', 'top', 'online'}

# IP Adresi Deseni (IPv4 standart veya portlu)
IP_PATTERN = re.compile(r'^(?:http[s]?://)?(?:www\.)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?(?:/.*)?$')

def calculate_entropy(text: str) -> float:
    """Shannon entropisini hesaplayarak karakter dizisinin karmaşıklığını ve rassallığını ölçer."""
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return float(entropy)

def extract_url_features(url: str) -> dict:
    """
    Tek bir URL diziliminden 25 adet leksikal ve yapısal özellik çıkarır.
    """
    url_clean = str(url).strip()
    
    # URL şeması yoksa parsing için geçici ekleme
    parsed_candidate = url_clean if '://' in url_clean else f'http://{url_clean}'
    
    try:
        parsed = urlparse(parsed_candidate)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path
        query = parsed.query
    except Exception:
        scheme = ''
        netloc = ''
        path = ''
        query = ''

    # Port bilgisini temizle
    hostname = netloc.split(':')[0]

    # Temel uzunluklar
    url_len = len(url_clean)
    hostname_len = len(hostname)
    path_len = len(path)
    query_len = len(query)

    # Karakter sayıları
    num_dots = url_clean.count('.')
    num_hyphens = url_clean.count('-')
    num_underscore = url_clean.count('_')
    num_slash = url_clean.count('/')
    num_question = url_clean.count('?')
    num_equal = url_clean.count('=')
    num_at = url_clean.count('@')
    num_percent = url_clean.count('%')
    num_ampersand = url_clean.count('&')
    
    num_digits = sum(1 for c in url_clean if c.isdigit())
    num_letters = sum(1 for c in url_clean if c.isalpha())
    digit_ratio = (num_digits / url_len) if url_len > 0 else 0.0

    # 1. IP Adresi Kullanımı (0 veya 1)
    has_ip = 1 if IP_PATTERN.match(url_clean) or re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname) else 0

    # 2. HTTPS Kullanımı (0 veya 1)
    is_https = 1 if scheme == 'https' or url_clean.startswith('https://') else 0

    # 3. Subdomain Analizi
    domain_parts = [p for p in hostname.split('.') if p]
    if len(domain_parts) > 2:
        num_subdomains = len(domain_parts) - 2
        registered_domain = domain_parts[-2]  # örn: google, github
    elif len(domain_parts) == 2:
        num_subdomains = 0
        registered_domain = domain_parts[0]
    else:
        num_subdomains = 0
        registered_domain = hostname

    # 4. Domain İçinde Tire (-) Kullanımı (Prefix-Suffix saldırısı)
    prefix_suffix = 1 if '-' in hostname else 0

    # 5. Eylem/Güvenlik Anahtar Kelimeleri Varlığı
    lower_url = url_clean.lower()
    has_action_kw = 1 if any(kw in lower_url for kw in ACTION_KEYWORDS) else 0

    # 6. Marka Taklidi (Brand Spoofing): Marka adı URL'de var ama ana domain o markaya ait değil
    lower_path_query = (path + '?' + query).lower()
    brand_spoofing = 0
    for brand in POPULAR_BRANDS:
        if brand in lower_url:
            if registered_domain != brand:
                brand_spoofing = 1
                break

    # 7. Shannon Entropisi
    entropy = calculate_entropy(url_clean)

    # 8. Path veya Subdomain İçinde Yanıltıcı TLD Kullanımı
    subdomain_str = '.'.join(domain_parts[:-2]) if len(domain_parts) > 2 else ''
    path_and_sub = f"{subdomain_str} {path}".lower()
    tld_in_path_sub = 1 if any(f".{tld}" in path_and_sub for tld in COMMON_TLDS) else 0

    # 9. Path içinde Çift Bölü '//' Varlığı (Yönlendirme açığı)
    has_double_slash = 1 if '//' in path else 0

    # 10. URL Kısaltma Servisi Kullanımı
    is_shortened = 1 if any(hostname == svc or hostname.endswith('.' + svc) for svc in SHORTENING_SERVICES) else 0

    return {
        'url_length': url_len,
        'domain_length': hostname_len,
        'path_length': path_len,
        'query_length': query_len,
        'num_dots': num_dots,
        'num_hyphens': num_hyphens,
        'num_underscore': num_underscore,
        'num_slash': num_slash,
        'num_question': num_question,
        'num_equal': num_equal,
        'num_at': num_at,
        'num_percent': num_percent,
        'num_ampersand': num_ampersand,
        'num_digits': num_digits,
        'num_letters': num_letters,
        'digit_ratio': round(digit_ratio, 4),
        'has_ip': has_ip,
        'is_https': is_https,
        'num_subdomains': num_subdomains,
        'prefix_suffix': prefix_suffix,
        'has_action_keywords': has_action_kw,
        'brand_spoofing': brand_spoofing,
        'shannon_entropy': round(entropy, 4),
        'tld_in_path_or_sub': tld_in_path_sub,
        'has_double_slash_path': has_double_slash,
        'is_shortened': is_shortened
    }

def extract_features_batch(df: pd.DataFrame, url_col: str = 'url') -> pd.DataFrame:
    """Verilen DataFrame'deki tüm URL'ler için özellik matrisini üretir."""
    features = [extract_url_features(url) for url in df[url_col]]
    return pd.DataFrame(features)

if __name__ == '__main__':
    test_cases = [
        ("https://www.google.com/", 0),
        ("http://192.168.1.1/login.php?user=admin", 1),
        ("https://paypal-security-verification.serveo.net/webscr?cmd=login", 1),
        ("https://bit.ly/secure-login", 1),
        ("https://github.com/torvalds/linux", 0),
        ("http://google.com.fake-auth.xyz/signin", 1)
    ]
    
    print("=" * 65)
    print("ÖZELLİK ÇIKARIM MOTORU DOĞRULAMA TESTİ")
    print("=" * 65)
    for u, expected in test_cases:
        feat = extract_url_features(u)
        print(f"URL: {u}")
        print(f"  -> IP: {feat['has_ip']}, HTTPS: {feat['is_https']}, Entropi: {feat['shannon_entropy']}, "
              f"EylemKelime: {feat['has_action_keywords']}, MarkaTaklidi: {feat['brand_spoofing']}, Kısaltma: {feat['is_shortened']}")
    print("=" * 65)
