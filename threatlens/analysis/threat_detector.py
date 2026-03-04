from analysis.url_analyzer import detect_ip_url, detect_suspicious_tld, detect_shortened_url, detect_long_url
from analysis.url_analyzer import detect_ip_domain
from analysis.threat_manager import create_threat

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

    for domain in domains:

        if detect_suspicious_tld(domain):
            score += 3
            indicators.append("suspicious_tld")

        if detect_ip_domain(domain):
            score += 4
            indicators.append("ip_domain")

    return score, indicators


# ------------------------------
# SEVERITY CLASSIFICATION
# ------------------------------

def classify_severity(score):

    if score >= 6:
        return "High"

    elif score >= 3:
        return "Medium"

    else:
        return "Low"


# ------------------------------
# MAIN POST ANALYSIS PIPELINE
# ------------------------------

def analyze_post(post, keywords, urls, domains):

    # Keyword analysis
    keyword_score, keyword_indicators = calculate_threat_score(keywords)

    # URL analysis
    url_score, url_indicators = analyze_urls(urls, domains)

    # Combine scores
    total_score = keyword_score + url_score

    # Combine indicators
    indicators = list(set(keyword_indicators + url_indicators))

    # Classify severity
    severity = classify_severity(total_score)

    # Save threat
    if total_score > 0 and post is not None:
        create_threat(post, total_score, severity, indicators)

    return total_score, severity, indicators