import re


def extract_urls(text):

    url_pattern = r"https?://[^\s]+"
    return re.findall(url_pattern, text)


def extract_domains(urls):

    domains = []

    for url in urls:
        domain = url.split("//")[-1].split("/")[0]
        domains.append(domain)

    return domains


def extract_emails(text):

    email_pattern = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
    return re.findall(email_pattern, text)


def extract_ips(text):

    ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
    return re.findall(ip_pattern, text)


def extract_crypto_wallets(text):

    btc_pattern = r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"
    return re.findall(btc_pattern, text)