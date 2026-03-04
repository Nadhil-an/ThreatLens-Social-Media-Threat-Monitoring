import re


def detect_ip_url(url):
    pattern = r"https?://\d+\.\d+\.\d+\.\d+"
    return re.search(pattern, url)


def detect_suspicious_tld(domain):
    suspicious_tlds = [".xyz", ".top", ".ru", ".tk"]

    for tld in suspicious_tlds:
        if domain.endswith(tld):
            return True

    return False

def detect_ip_domain(domain):

    ip_pattern = r"^\d+\.\d+\.\d+\.\d+$"

    if re.match(ip_pattern, domain):
        return True

    return False


def detect_shortened_url(url):

    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl"
    ]

    for short in shorteners:
        if short in url:
            return True

    return False


def detect_suspicious_tld(domain):

    suspicious_tlds = [
        ".xyz",
        ".top",
        ".ru",
        ".tk"
    ]

    for tld in suspicious_tlds:
        if domain.endswith(tld):
            return True

    return False


def detect_long_url(url):

    if len(url) > 75:
        return True

    return False