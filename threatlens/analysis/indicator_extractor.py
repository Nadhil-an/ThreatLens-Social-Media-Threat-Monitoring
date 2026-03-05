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

    for url in urls:

        if not url.startswith("http"):
            url = "http://" + url

        parsed = urlparse(url)

        if parsed.netloc:
            domains.append(parsed.netloc)

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