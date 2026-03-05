from analysis.url_analyzer import (
    detect_ip_url,
    detect_suspicious_tld,
    detect_shortened_url,
    detect_long_url,
    detect_ip_domain
)
from analysis.threat_scoring import calculate_final_score, classify_severity
from analysis.threat_manager import create_threat
from analysis.threat_intel import check_domain_virustotal
from analysis.hash_extractor import extract_hashes
from analysis.hash_analyzer import analyze_hash


# ------------------------------
# KEYWORD THREAT SCORING
# ------------------------------

def calculate_threat_score(keywords):

    score = 0
    indicators = []

    keyword_scores = {
        "free giveaway": 2,
        "verify account": 2,
        "urgent": 1,
        "crypto investment": 3,
        "click here": 2,
    }

    for keyword in keywords:

        for k in keyword_scores:

            if k in keyword.lower():
                score += keyword_scores[k]
                indicators.append(k)

    return score, indicators


# ------------------------------
# URL & DOMAIN ANALYSIS
# ------------------------------

def analyze_urls(urls, domains):

    score = 0
    indicators = []

    # URL analysis
    for url in urls:

        if detect_ip_url(url):
            score += 4
            indicators.append("ip_url")

        if detect_shortened_url(url):
            score += 2
            indicators.append("shortened_url")

        if detect_long_url(url):
            score += 1
            indicators.append("long_url")

    # Domain analysis
    for domain in domains:

        vt_score = check_domain_virustotal(domain)

        if vt_score is not None and vt_score > 0:
            score += 5
            indicators.append("malicious_domain_vt")

        if detect_suspicious_tld(domain):
            score += 3
            indicators.append("suspicious_tld")

        if detect_ip_domain(domain):
            score += 4
            indicators.append("ip_domain")

    return score, indicators


# ------------------------------
# HASH / MALWARE ANALYSIS
# ------------------------------

def analyze_hashes(post_text):

    score = 0
    indicators = []

    hashes = extract_hashes(post_text)

    # MD5 hashes
    for md5 in hashes["md5"]:

        result = analyze_hash(md5)

        if result and result["score"] > 0:
            score += result["score"]
            indicators.append("malicious_md5_hash")

    # SHA256 hashes
    for sha in hashes["sha256"]:

        result = analyze_hash(sha)

        if result and result["score"] > 0:
            score += result["score"]
            indicators.append("malicious_sha256_hash")

    return score, indicators


# ------------------------------
# SEVERITY CLASSIFICATION
# ------------------------------

def classify_severity(score):

    if score >= 8:
        return "High"

    elif score >= 4:
        return "Medium"

    else:
        return "Low"


# ------------------------------
# THREAT TYPE CLASSIFICATION
# ------------------------------

def classify_threat_type(post_text, urls, domains, indicators):

    text = post_text.lower()

    if "ip_url" in indicators or "ip_domain" in indicators:
     return "Credential Harvesting"

    if "malicious_md5_hash" in indicators or "malicious_sha256_hash" in indicators:
        return "Malware Distribution"

    phishing_keywords = ["verify", "login", "account", "update", "password"]
    if any(k in text for k in phishing_keywords):
        return "Phishing"

    crypto_keywords = ["crypto", "bitcoin", "btc", "wallet"]
    if any(k in text for k in crypto_keywords):
        return "Crypto Scam"

    giveaway_keywords = ["giveaway", "reward", "free"]
    if any(k in text for k in giveaway_keywords):
        return "Scam"

    if "suspicious_tld" in indicators:
        return "Phishing"

    if "malicious_md5_hash" in indicators or "malicious_sha256_hash" in indicators:
        return "Malware Distribution"

    return "Suspicious"


# ------------------------------
# MAIN POST ANALYSIS PIPELINE
# ------------------------------

def analyze_post(post, keywords, urls, domains, ips, hashes):

    # Keyword analysis
    keyword_score, keyword_indicators = calculate_threat_score(keywords)

    # URL analysis
    url_score, url_indicators = analyze_urls(urls, domains)

    # Hash analysis
    hash_score, hash_indicators = analyze_hashes(post.content)

    # Final scoring
    total_score = calculate_final_score(keyword_score, url_score, hash_score)

    # Debug logs (ADD HERE)
    print("Keyword score:", keyword_score)
    print("URL score:", url_score)
    print("Hash score:", hash_score)
    print("Final score:", total_score)

    # Combine indicators
    indicators = list(set(
        keyword_indicators +
        url_indicators +
        hash_indicators
    ))

    severity = classify_severity(total_score)

    threat_type = classify_threat_type(
        post.content,
        urls,
        domains,
        indicators
    )

    if total_score > 0 and post is not None:
        create_threat(post, threat_type, total_score, severity, indicators)

    return threat_type, total_score, severity, indicators