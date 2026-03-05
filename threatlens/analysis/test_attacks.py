from analysis.threat_detector import analyze_post
from analysis.ioc_extractor import extract_urls, extract_domains, extract_emails, extract_ips, extract_crypto_wallets

# Simulated phishing posts
attack_posts = [

    "Urgent! Verify your PayPal account now https://paypal-security-login.xyz",

    "Free giveaway! Send crypto and receive double reward",

    "Amazon alert: verify your account immediately http://amazon-login-support.top",

    "Instagram support: reset your password here https://instagram-help.xyz",

    "Login to your bank account here http://192.168.1.100/login"

]

def simulate_attacks():

    for post in attack_posts:

        print("\nAnalyzing Post:")
        print(post)

        keywords = post.lower().split()

        urls = extract_urls(post)
        domains = extract_domains(urls)

        emails = extract_emails(post)
        ips = extract_ips(post)
        wallets = extract_crypto_wallets(post)

        print("URLs:", urls)
        print("Domains:", domains)
        print("Emails:", emails)
        print("IPs:", ips)
        print("Crypto Wallets:", wallets)

        threat_type, score, severity, indicators = analyze_post(None, keywords, urls, domains)
        print("Threat Type:", threat_type)
        print("Score:", score)
        print("Severity:", severity)
        print("Indicators:", indicators)


if __name__ == "__main__":
    simulate_attacks()