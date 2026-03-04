from analysis.threat_detector import analyze_post


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

        # simple extraction
        keywords = post.lower().split()

        urls = []
        domains = []

        for word in post.split():

            if "http" in word:
                urls.append(word)

                domain = word.split("//")[-1].split("/")[0]
                domains.append(domain)

        score, severity, indicators = analyze_post(None, keywords, urls, domains)

        print("Score:", score)
        print("Severity:", severity)
        print("Indicators:", indicators)


if __name__ == "__main__":
    simulate_attacks()