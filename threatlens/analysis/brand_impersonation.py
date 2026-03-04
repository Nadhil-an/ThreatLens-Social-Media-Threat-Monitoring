from urllib.parse import urlparse
import difflib


def similarity(a, b):
    return difflib.SequenceMatcher(None, a, b).ratio()

def extract_main_word(domain):

    domain = domain.split(".")[0]

    parts = domain.split("-")

    return parts[0]

def detect_brand_impersonation(domain, brands):

    suspicious = []

    main_word = extract_main_word(domain)

    for brand in brands:

        score = similarity(main_word.lower(), brand.lower())

        if score > 0.8 and domain != brand + ".com":

            suspicious.append({
                "brand": brand,
                "domain": domain,
                "similarity": score
            })

    return suspicious