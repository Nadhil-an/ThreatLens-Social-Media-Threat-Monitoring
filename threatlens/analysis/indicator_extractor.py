import re
from urllib.parse import urlparse


# -----------------------------
# URL EXTRACTION
# -----------------------------

def extract_urls(text):

    url_pattern = r'https?://[^\s]+|www\.[^\s]+'
    urls = re.findall(url_pattern, text)

    return urls


# -----------------------------
# DOMAIN EXTRACTION
# -----------------------------

def extract_domains(text):

    urls = extract_urls(text)
    domains = []
    
    # Simple regex to check if string is an IPv4 address
    ip_pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')

    for url in urls:
        if not url.startswith("http"):
            url = "http://" + url

        parsed = urlparse(url)

        if parsed.netloc:
            # Remove port if present (e.g., domain.com:8080 -> domain.com)
            domain = parsed.netloc.split(':')[0]
            
            # Only add to domains if it's NOT an IP address
            if not ip_pattern.match(domain):
                domains.append(domain)

    return domains


# -----------------------------
# IP ADDRESS EXTRACTION
# -----------------------------

def extract_ips(text):

    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'

    ips = re.findall(ip_pattern, text)

    return ips


# -----------------------------
# HASH EXTRACTION
# -----------------------------


def extract_hashes(text):

    md5_pattern = r'\b[a-fA-F0-9]{32}\b'
    sha256_pattern = r'\b[a-fA-F0-9]{64}\b'

    md5_hashes = re.findall(md5_pattern, text)
    sha256_hashes = re.findall(sha256_pattern, text)

    hashes = md5_hashes + sha256_hashes

    return hashes


# -----------------------------
# KEYWORD EXTRACTION
# -----------------------------

def extract_keywords(text):

    keywords = [
        "free giveaway",
        "verify account",
        "urgent",
        "crypto investment",
        "click here",
        "limited offer"
    ]

    detected = []

    for word in keywords:
        if word.lower() in text.lower():
            detected.append(word)

    return detected


# -----------------------------
# EMAIL EXTRACTION
# -----------------------------

def extract_emails(text):
    email_pattern = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
    return re.findall(email_pattern, text)


# -----------------------------
# CRYPTO WALLET EXTRACTION
# -----------------------------

def extract_crypto_wallets(text):
    btc_pattern = r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'
    return re.findall(btc_pattern, text)