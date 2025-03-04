import discord
import hashlib
import os
import random
import re
import aiohttp

# Enter your bot token here
TOKEN = "YOUR_DISCORD_BOT_TOKEN"

# Set up Discord intents
intents = discord.Intents.default()
intents.message_content = True
intents.guilds = True
intents.attachments = True

client = discord.Client(intents=intents)

# Known malware families and hashes (expand this for better accuracy)
MALWARE_SIGNATURES = {
    "Blank grabber": ["d41d8cd98f00b204e9800998ecf8427e"],  # Example hash
    "Luna grabber": ["f5d1278e8109edd94e1e4197e04873b9"],  # Example hash
    "Empyrean": ["0cc175b9c0f1b6a831c399e269772661"],  # Example hash
    "Xworm": ["92eb5ffee6ae2fec3ad71c777531578f"],  # Example hash
}

# Suspicious keywords/functions (expand this for more accuracy)
SUSPICIOUS_KEYWORDS = [
    "discord.com/api/webhooks", "requests.post", "subprocess.run", "os.system",
    "stealer", "password", "token grabber", "keylogger", "exec", "eval"
]

# Webhook spam message
SPAM_MESSAGE = "@everyone STOP RATTING YOU SKID💀"

# Regex patterns to detect Discord webhooks and bot tokens
WEBHOOK_REGEX = r"https:\/\/discord\.com\/api\/webhooks\/\d+\/[\w-]+"
BOT_TOKEN_REGEX = r"[A-Za-z\d]{24}\.[\w-]{6}\.[\w-]{27}"  # Matches Discord bot token format

def get_file_source_ip():
    """Simulates retrieving the source IPv4 address of the uploaded file."""
    return f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"

def get_file_source_ipv6():
    """Simulates retrieving the source IPv6 address of the uploaded file."""
    return f"2001:0db8:{random.randint(1000, 9999)}:{random.randint(1000, 9999)}::{random.randint(1, 100)}"

def detect_malware(file_hash, file_content):
    """Checks for malware based on known signatures and suspicious keywords."""
    detected_families = []

    # Check file hash against known malware hashes
    for malware, hashes in MALWARE_SIGNATURES.items():
        if file_hash in hashes:
            detected_families.append(malware)

    # Check for suspicious keywords
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in file_content.lower():
            detected_families.append("⚠️ Suspicious Code Detected")

    return detected_families if detected_families else ["Unknown"]

async def spam_webhook(webhook_url):
    """Spams the detected webhook with a warning message."""
    async with aiohttp.ClientSession() as session:
        for _ in range(5):  # Spam 5 times
            async with session.post(webhook_url, json={"content": SPAM_MESSAGE}) as response:
                print(f"Webhook spammed: {response.status}")

@client.event
async def on_ready():
    print(f"✅ Logged in as {client.user}")

@client.event
async def on_message(message):
    if message.author.bot:
        return
    
    # Command to start scanning
    if message.content.startswith(".scan"):
        await message.delete()
        await message.channel.send(f"{message.author.mention}, Please upload a file below this message to get info.")

    # Handle file uploads
    if message.attachments:
        attachment = message.attachments[0]
        file_path = f"./{attachment.filename}"
        await attachment.save(file_path)

        # Get file details
        file_size = os.path.getsize(file_path)
        file_hash = hashlib.sha256(open(file_path, "rb").read()).hexdigest()
        file_type = attachment.filename.split(".")[-1] if "." in attachment.filename else "Unknown"
        file_source_ip = get_file_source_ip()
        file_source_ipv6 = get_file_source_ipv6()

        # Read file content
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                file_content = f.read()
        except:
            file_content = "Binary file (not readable)"

        # Detect possible webhooks & bot tokens
        found_webhooks = re.findall(WEBHOOK_REGEX, file_content)
        found_tokens = re.findall(BOT_TOKEN_REGEX, file_content)

        # Check for malware
        detected_malware = detect_malware(file_hash, file_content)
        malware_family = ", ".join(detected_malware)

        # Create Embed for public message (without sensitive data)
        embed = discord.Embed(title="📁 File Analysis", color=discord.Color.blue())
        embed.add_field(name="📝 File Name", value=attachment.filename, inline=False)
        embed.add_field(name="📌 File Type", value=file_type, inline=True)
        embed.add_field(name="📦 File Size", value=f"{file_size} bytes", inline=True)
        embed.add_field(name="🔑 SHA-256 Hash", value=file_hash, inline=False)
        embed.add_field(name="🛑 Malware Family", value=malware_family, inline=False)
        embed.add_field(name="🌐 File Source IP", value=file_source_ip, inline=True)
        embed.add_field(name="🛰️ File Source IPv6", value=file_source_ipv6, inline=True)

        if found_webhooks:
            embed.add_field(name="🚨 Webhooks Found", value="⚠️ Webhooks detected! (Check DM for details)", inline=False)

        if found_tokens:
            embed.add_field(name="🔒 Possible Bot Tokens", value="⚠️ Possible bot tokens detected! (Check DM for details)", inline=False)

        if file_content != "Binary file (not readable)":
            embed.add_field(name="🖥️ File Source Code", value=f"```{file_content[:500]}```\n...", inline=False)

        await message.channel.send(embed=embed)

        # Send DM with sensitive details
        dm_embed = discord.Embed(title="🔍 Private File Analysis Report", color=discord.Color.red())
        dm_embed.add_field(name="📝 File Name", value=attachment.filename, inline=False)
        dm_embed.add_field(name="🔑 SHA-256 Hash", value=file_hash, inline=False)
        dm_embed.add_field(name="🛑 Malware Family", value=malware_family, inline=False)

        if found_webhooks:
            dm_embed.add_field(name="🚨 Webhooks Detected", value="\n".join(found_webhooks), inline=False)

        if found_tokens:
            dm_embed.add_field(name="🔒 Possible Bot Tokens", value="\n".join(found_tokens), inline=False)

        try:
            await message.author.send(embed=dm_embed)
        except discord.Forbidden:
            await message.channel.send(f"{message.author.mention}, I couldn't DM you! Please enable DMs.")

        # If webhooks are detected, ask if the user wants to spam them
        if found_webhooks:
            confirm_message = await message.channel.send(
                f"{message.author.mention}, Detected **{len(found_webhooks)}** webhooks in this file.\n"
                "React with ✅ to spam them with the message, or ❌ to ignore."
            )
            await confirm_message.add_reaction("✅")
            await confirm_message.add_reaction("❌")

        # Cleanup
        os.remove(file_path)

client.run(TOKEN)
