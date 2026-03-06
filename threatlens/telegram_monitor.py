import os
import sys
import asyncio
from telethon import TelegramClient, events

# ==========================================
# 1. SETUP DJANGO ENVIRONMENT
# ==========================================
# This allows the script to use Django models and functions
# outside of the normal 'manage.py runserver' web environment.
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "threatlens.settings")

import django
django.setup()

# Import your existing ThreatLens logic
from posts.models import Post
from threats.models import Indicator
from analysis.indicator_extractor import (
    extract_urls, extract_domains, extract_keywords, extract_ips, extract_hashes
)
from analysis.threat_detector import analyze_post

# ==========================================
# 2. TELEGRAM API CREDENTIALS
# ==========================================
# Keys are safely loaded from the .env file
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

API_ID = os.environ.get("TELEGRAM_API_ID")
API_HASH = os.environ.get("TELEGRAM_API_HASH")

# Which channel or group do you want to monitor?
# You can use a username like '@CryptoScams' or an invite link.
# For testing, you can use a test group you create, or 'me' to monitor your Saved Messages.
TARGET_CHANNEL = "me" 

# ==========================================
# 3. CREATE THE TELEGRAM CLIENT
# ==========================================
# 'threatlens_session' is the name of the file it will create to save your login session
client = TelegramClient('threatlens_session', API_ID, API_HASH)

# ==========================================
# 4. LISTEN FOR NEW MESSAGES
# ==========================================
@client.on(events.NewMessage(chats=TARGET_CHANNEL))
async def handle_new_message(event):
    message_text = event.message.text
    
    if not message_text:
        return # Ignore empty messages (e.g., just a photo with no caption)

    print(f"\n[+] New message detected in {TARGET_CHANNEL}!")
    print(f"Content: {message_text[:100]}...")

    # Run the Django analysis in a background thread so it doesn't block Telegram
    await asyncio.to_thread(process_threatlens_pipeline, message_text)

# ==========================================
# 5. THREATLENS ANALYSIS PIPELINE
# ==========================================
def process_threatlens_pipeline(text):
    try:
        # Create a new Post in the database
        post_obj = Post.objects.create(content=text, source=f"Telegram ({TARGET_CHANNEL})")

        # Extract indicators
        urls     = extract_urls(text)
        domains  = extract_domains(text)
        keywords = extract_keywords(text)
        ips      = extract_ips(text)
        hashes   = extract_hashes(text)

        # Save extracted indicators
        for u in urls: Indicator.objects.get_or_create(indicator_type="url", value=u)
        for d in domains: Indicator.objects.get_or_create(indicator_type="domain", value=d)
        for k in keywords: Indicator.objects.get_or_create(indicator_type="keyword", value=k)
        for i in ips: Indicator.objects.get_or_create(indicator_type="ip", value=i)
        for h in hashes: Indicator.objects.get_or_create(indicator_type="hash", value=h)

        # Run the AI/logic threat analysis
        threat_type, score, severity, indicators, mitre = analyze_post(
            post_obj, keywords, urls, domains, ips, hashes
        )

        print(f"   -> Result: {severity} Severe ({threat_type}) - Score: {score}")

    except Exception as e:
        print(f"   -> Error analyzing message: {str(e)}")


# ==========================================
# 6. START THE MONITOR
# ==========================================
if __name__ == '__main__':
    if not API_ID or not API_HASH:
        print("ERROR: You must fill in API_ID and API_HASH in the script first!")
        sys.exit(1)

    print("Starting ThreatLens Telegram Auto-Monitor...")
    print(f"Listening to: {TARGET_CHANNEL}")
    
    client.start()
    client.run_until_disconnected()
