import re
from urllib.parse import urlparse


def extract_urls(text):
    url_pattern = r'https?://[^\s]+|www\.[^\s]+'
    urls = re.findall(url_pattern, text)
    return urls


def extract_domains(urls):
    domains = []

    for url in urls:
        parsed = urlparse(url)
        domain = parsed.netloc
        domains.append(domain)

    return domains


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