# ----------------------------------------
# THREAT INDICATOR SCORES
# ----------------------------------------

THREAT_SCORES = {

    # Keyword based threats
    "free_giveaway": 2,
    "verify_account": 2,
    "urgent_action": 1,
    "crypto_investment": 2,
    "click_here": 1,

    # Domain / URL indicators
    "suspicious_tld": 2,
    "shortened_url": 2,
    "long_url": 1,
    "ip_url": 3,
    "ip_domain": 3,

    # Reputation indicators
    "malicious_domain_vt": 4,

    # Malware indicators
    "malicious_md5_hash": 5,
    "malicious_sha256_hash": 6,

    # Impersonation indicators
    "brand_impersonation": 4,
    "username_impersonation": 3
}


# ----------------------------------------
# FINAL SCORE CALCULATION
# ----------------------------------------

def calculate_final_score(keyword_score, url_score, hash_score):

    total_score = keyword_score + url_score + hash_score

    # Cap the maximum score to 10
    if total_score > 10:
        total_score = 10

    return total_score


# ----------------------------------------
# GENERIC INDICATOR SCORING
# ----------------------------------------

def calculate_indicator_score(indicators):

    score = 0
    reasons = []

    for indicator in indicators:

        if indicator in THREAT_SCORES:

            score += THREAT_SCORES[indicator]
            reasons.append(indicator)

    return score, reasons


# ----------------------------------------
# SEVERITY CLASSIFICATION
# ----------------------------------------

def classify_severity(score):

    if score >= 8:
        return "High"

    elif score >= 4:
        return "Medium"

    else:
        return "Low"