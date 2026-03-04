import difflib


def similarity(a, b):
    return difflib.SequenceMatcher(None, a, b).ratio()


def extract_base_username(username):

    parts = username.split("_")

    return parts[0]

def detect_username_impersonation(username, brands):

    suspicious = []

    base_name = extract_base_username(username)

    suspicious_keywords = [
        "support",
        "help",
        "security",
        "team",
        "admin",
        "service",
        "official"
    ]

    for brand in brands:

        score = similarity(base_name.lower(), brand.lower())

        # similarity attack
        if score > 0.7 and base_name.lower() != brand.lower():

            suspicious.append({
                "brand": brand,
                "username": username,
                "reason": "Username similar to brand",
                "similarity": score
            })

        # brand keyword attack
        if brand.lower() in username.lower():

            for keyword in suspicious_keywords:

                if keyword in username.lower():

                    suspicious.append({
                        "brand": brand,
                        "username": username,
                        "reason": "Brand + support keyword"
                    })

    return suspicious