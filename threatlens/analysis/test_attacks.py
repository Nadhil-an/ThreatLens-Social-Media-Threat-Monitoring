import os
import sys
import django

# Setup Django environment
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "threatlens.settings")
django.setup()

from analysis.threat_detector import analyze_post
from analysis.indicator_extractor import (
    extract_urls, extract_domains, extract_emails, extract_ips, extract_crypto_wallets, extract_hashes
)

# Mock Post class for testing without a database
class MockPost:
    def __init__(self, content):
        self.content = content

# Simulated phishing posts
attack_posts = [
    "Urgent! Verify your PayPal account now https://paypal-security-login.xyz",
    "Free giveaway! Send crypto and receive double reward",
    "Amazon alert: verify your account immediately http://amazon-login-support.top",
    "Instagram support: reset your password here https://instagram-help.xyz",
    "Login to your bank account here http://192.168.1.100/login"
]

def simulate_attacks():
    for post_text in attack_posts:
        print("\nAnalyzing Post:")
        print(post_text)

        # Use consistent extraction from indicator_extractor
        keywords = post_text.lower().split()
        urls = extract_urls(post_text)
        domains = extract_domains(post_text)
        emails = extract_emails(post_text)
        ips = extract_ips(post_text)
        wallets = extract_crypto_wallets(post_text)
        hashes = extract_hashes(post_text)

        print("URLs:", urls)
        print("Domains:", domains)
        print("Emails:", emails)
        print("IPs:", ips)
        print("Crypto Wallets:", wallets)
        print("Hashes:", hashes)

        # Mock object to satisfy the post.content requirement
        post_obj = MockPost(post_text)

        # Signature: def analyze_post(post, keywords, urls, domains, ips, hashes)
        # Returns: threat_type, total_score, severity, indicators, mitre
        threat_type, score, severity, indicators, mitre = analyze_post(
            post_obj, keywords, urls, domains, ips, hashes
        )

        print("Threat Type:", threat_type)
        print("Score:", score)
        print("Severity:", severity)
        print("Indicators:", indicators)
        print("MITRE:", mitre)


if __name__ == "__main__":
    simulate_attacks()