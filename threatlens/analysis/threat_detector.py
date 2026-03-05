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
from analysis.mitre_mapper import map_mitre


# ----------------------------------
# KEYWORD ANALYSIS
# ----------------------------------

def analyze_keywords(keywords):

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
        text = keyword.lower()

        for rule in keyword_scores:

            if rule in text:
                score += keyword_scores[rule]
                indicators.append(rule)

    return score, indicators


# ----------------------------------
# URL & DOMAIN ANALYSIS
# ----------------------------------

def analyze_urls(urls, domains):

    score = 0
    indicators = []

    for url in urls:

        if detect_ip_url(url):
            score += 3
            indicators.append("ip_url")

        if detect_shortened_url(url):
            score += 2
            indicators.append("shortened_url")

        if detect_long_url(url):
            score += 1
            indicators.append("long_url")

    for domain in domains:

        vt_score = check_domain_virustotal(domain)

        if vt_score and vt_score > 0:
            score += 4
            indicators.append("malicious_domain_vt")

        if detect_suspicious_tld(domain):
            score += 2
            indicators.append("suspicious_tld")

        if detect_ip_domain(domain):
            score += 3
            indicators.append("ip_domain")

    return score, indicators


# ----------------------------------
# HASH ANALYSIS
# ----------------------------------

def analyze_hashes(post_text):

    score = 0
    indicators = []

    hashes = extract_hashes(post_text)

    # MD5
    for md5 in hashes["md5"]:

        result = analyze_hash(md5)

        if result and result["score"] > 0:
            score += 5
            indicators.append("malicious_md5_hash")

    # SHA256
    for sha in hashes["sha256"]:

        result = analyze_hash(sha)

        if result and result["score"] > 0:
            score += 6
            indicators.append("malicious_sha256_hash")

    return score, indicators


# ----------------------------------
# THREAT TYPE CLASSIFICATION
# ----------------------------------

def classify_threat_type(post_text, indicators):

    text = post_text.lower()

    if "malicious_md5_hash" in indicators or "malicious_sha256_hash" in indicators:
        return "Malware Distribution"

    if "ip_url" in indicators or "ip_domain" in indicators:
        return "Credential Harvesting"

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

    return "Suspicious"


# ----------------------------------
# MAIN ANALYSIS PIPELINE
# ----------------------------------

def analyze_post(post, keywords, urls, domains, ips, hashes):

    # Keyword analysis
    keyword_score, keyword_indicators = analyze_keywords(keywords)

    # URL analysis
    url_score, url_indicators = analyze_urls(urls, domains)

    # Hash analysis
    hash_score, hash_indicators = analyze_hashes(post.content)

    # Final score
    total_score = calculate_final_score(
        keyword_score,
        url_score,
        hash_score
    )

    # Combine indicators
    indicators = list(set(
        keyword_indicators +
        url_indicators +
        hash_indicators
    ))

    # Severity
    severity = classify_severity(total_score)

    # Threat type
    threat_type = classify_threat_type(
        post.content,
        indicators
    )

    # MITRE ATT&CK mapping
    mitre = map_mitre(threat_type)

    # Save threat
    if total_score > 0 and post is not None:
        create_threat(
            post,
            threat_type,
            total_score,
            severity,
            indicators
        )

    return threat_type, total_score, severity, indicators, mitre