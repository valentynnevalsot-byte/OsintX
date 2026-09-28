#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OsintX - OSINT Toolkit
Author: Injektor
For authorized security testing / research only.

Dependencies (all optional, modules degrade gracefully):
    pip install phonenumbers requests pillow colorama discord.py
"""

import os
import sys
import json
import time
import socket
import platform
import subprocess

# ---------------------------------------------------------------------------
# Optional dependency handling
# ---------------------------------------------------------------------------
try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAVE_COLOR = True
except ImportError:
    HAVE_COLOR = False

try:
    import phonenumbers
    from phonenumbers import geocoder, carrier, timezone
    HAVE_PHONE = True
except ImportError:
    HAVE_PHONE = False

try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    HAVE_PIL = True
except ImportError:
    HAVE_PIL = False


# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
class C:
    if HAVE_COLOR:
        R = Fore.RED; G = Fore.GREEN; Y = Fore.YELLOW
        B = Fore.BLUE; M = Fore.MAGENTA; CY = Fore.CYAN; W = Fore.WHITE
        RESET = Style.RESET_ALL; BOLD = Style.BRIGHT
    else:
        R = G = Y = B = M = CY = W = RESET = BOLD = ""


ADMIN_CODE = "6958"
VERSION = "1.0.0"

BANNER = r"""
          ..::::-==-.                                                  .:==-::::..
          .:---:.. -+*=                                                        =*+. ..:---:
         -+=.      :=++-..  ....::::-::::::::::::::::::::::::::::-::::...   .:-+=-.      :++-
 --:..   -+=:.        .::::---=+++=.:.                          ::.=+++=---::::.        .:=+-   ..:-
 .-=----:::-===-=-:::::::-------:.                                  .:-------:::::::---===--:--:-==-
   .:--:::--::-==+=-.  ..-:..                  ..    ..                  ..:-..  .-=+=-:::=-:::--:.
      .....:::::-++-.     ..:::--:::-:::::....--      --...:::::--:::--:::..     .-+=:::::::....
                ::-::--::.  .:::--:::..  .  :=-.      .=-.     ..::---:::.  .::-:::-:.
                      .:==-.::::.:::-=--::::-==-::..::-==-::::-=--:::::::..-+=:.
                           ....:::-=-:=+=-=-::-::----::-::---=+=:-=-::....
                                   ...::-==--::.....:..::-----::...
                                           ................
"""

MENU = f"""
{C.CY}{C.BOLD}  ┌──────────────────────────────────────────────────────┐
  │                     OsintX  v{VERSION}                     │
  ├──────────────────────────────────────────────────────┤
  │  {C.G}[01]{C.W}  Name Tracer                                  │
  │  {C.G}[02]{C.W}  Phone Number Tracer                          │
  │  {C.G}[03]{C.W}  IP Lookup                                    │
  │  {C.G}[04]{C.W}  Discord Nick Lookup                          │
  │  {C.G}[05]{C.W}  Foto Analyzer                                │
  │  {C.G}[06]{C.W}  Wi-Fi Tracer                                 │
  │  {C.G}[07]{C.W}  WhatsApp Tracer                              │
  │  {C.G}[08]{C.W}  DIS Trac                                     │
  │  {C.G}[09]{C.W}  Auto All Trac                                │
  │  {C.G}[10]{C.W}  Admin Join                                   │
  │  {C.G}[11]{C.W}  Update                                       │
  │  {C.G}[12]{C.W}  Exit                                         │
  └──────────────────────────────────────────────────────┘{C.RESET}
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def clear():
    os.system("cls" if os.name == "nt" else "clear")


def header(title):
    print(f"\n{C.M}{C.BOLD}[*] {title}{C.RESET}")
    print(f"{C.M}" + "-" * 56 + f"{C.RESET}")


def ok(msg):    print(f"{C.G}[+] {msg}{C.RESET}")
def warn(msg):  print(f"{C.Y}[!] {msg}{C.RESET}")
def err(msg):   print(f"{C.R}[x] {msg}{C.RESET}")
def info(msg):  print(f"{C.CY}[i] {msg}{C.RESET}")


def pause():
    input(f"\n{C.W}Press ENTER to return to menu...{C.RESET}")


def ask(prompt):
    return input(f"{C.CY}{prompt}{C.RESET}").strip()


def get_json(url, timeout=10):
    """GET a URL and return parsed JSON, or None."""
    if not HAVE_REQUESTS:
        err("The 'requests' library is not installed.  pip install requests")
        return None
    try:
        r = requests.get(url, timeout=timeout,
                         headers={"User-Agent": "OsintX/1.0"})
        r.raise_for_status()
        return r.json()
    except Exception as e:
        err(f"Request failed: {e}")
        return None


# ---------------------------------------------------------------------------
# 1. Name Tracer
# ---------------------------------------------------------------------------
def name_tracer():
    header("Name Tracer")
    name = ask("Target full name: ")
    if not name:
        warn("Empty input.")
        return

    info(f"Building public-source profile for: {name}")

    # Public search-engine style endpoints (no key required).
    engines = {
        "Google": f"https://www.google.com/search?q=%22{name.replace(' ', '+')}%22",
        "Bing":   f"https://www.bing.com/search?q=%22{name.replace(' ', '+')}%22",
        "DuckDuckGo (html)": f"https://html.duckduckgo.com/html/?q=%22{name.replace(' ', '+')}%22",
    }

    print()
    for label, url in engines.items():
        print(f"  {C.G}›{C.W} {label:<18} {url}")

    print()
    info("Open the links above in a browser to review public hits.")
    info("Automated scraping of these engines violates their ToS, so OsintX")
    info("only generates the queries. For API-based results use a provider")
    info("such as SerpAPI / Google Custom Search with your own key.")
    pause()


# ---------------------------------------------------------------------------
# 2. Phone Number Tracer
# ---------------------------------------------------------------------------
def phone_tracer():
    header("Phone Number Tracer")
    num = ask("Phone number (e.g. +420123456789): ")
    if not num:
        warn("Empty input.")
        return

    if not HAVE_PHONE:
        warn("phonenumbers not installed -> pip install phonenumbers")
        info("Showing raw digits only:")
        print(f"  {C.G}›{C.W} {num}")
        pause()
        return

    try:
        p = phonenumbers.parse(num, None)
    except phonenumbers.NumberParseException as e:
        err(f"Parse error: {e}")
        pause()
        return

    print()
    print(f"  {C.G}Valid number {C.W}: {'YES' if phonenumbers.is_valid_number(p) else 'NO'}")
    print(f"  {C.G}Possible     {C.W}: {'YES' if phonenumbers.is_possible_number(p) else 'NO'}")
    print(f"  {C.G}Country code {C.W}: +{p.country_code}")
    print(f"  {C.G}National     {C.W}: {p.national_number}")
    print(f"  {C.G}Region       {C.W}: {geocoder.description_for_number(p, 'en') or 'unknown'}")
    print(f"  {C.G}Carrier      {C.W}: {carrier.name_for_number(p, 'en') or 'unknown'}")
    print(f"  {C.G}Timezone     {C.W}: {', '.join(timezone.time_zones_for_number(p)) or 'unknown'}")

    info("WhatsApp quick-check link:")
    print(f"  {C.G}›{C.W} https://wa.me/{num.replace('+', '').replace(' ', '')}")
    pause()


# ---------------------------------------------------------------------------
# 3. IP Lookup
# ---------------------------------------------------------------------------
def ip_lookup():
    header("IP Lookup")
    ip = ask("IP address (blank = your public IP): ")
    if not ip:
        ip = ""

    data = get_json(f"http://ip-api.com/json/{ip}?fields=status,message,country,"
                    f"regionName,city,zip,lat,lon,timezone,isp,org,as,query")
    if not data:
        pause()
        return

    if data.get("status") != "success":
        err(data.get("message", "Lookup failed."))
        pause()
        return

    print()
    for k in ("query", "country", "regionName", "city", "zip",
              "lat", "lon", "timezone", "isp", "org", "as"):
        if k in data:
            print(f"  {C.G}{k:<11}{C.W}: {data[k]}")
    pause()


# ---------------------------------------------------------------------------
# 4. Discord Nick Lookup
# ---------------------------------------------------------------------------
def discord_nick():
    header("Discord Nick Lookup")
    user = ask("Discord username (without @): ")
    if not user:
        warn("Empty input.")
        return

    info("Note: Discord disabled programmatic username lookup (username "
         "enumeration) on its public API, so an automated query returns 401.")
    print()
    print(f"  {C.G}›{C.W} Profile URL : https://discord.com/users/{user}")
    print(f"  {C.G}›{C.W} Search URL  : https://discord.com/search?q={user}")
    info("If you supply a bot token + user ID you can pull full profile data")
    info("via the official API: https://discord.com/api/v10/users/<id>")
    pause()


# ---------------------------------------------------------------------------
# 5. Foto Analyzer (EXIF / metadata)
# ---------------------------------------------------------------------------
def _dms_to_deg(v):
    d, m, s = v
    return d + (m / 60.0) + (s / 3600.0)


def foto_analyzer():
    header("Foto Analyzer")
    path = ask("Path to image file: ").strip('"')
    if not os.path.isfile(path):
        err("File not found.")
        pause()
        return
    if not HAVE_PIL:
        warn("Pillow not installed -> pip install pillow")
        pause()
        return

    try:
        img = Image.open(path)
    except Exception as e:
        err(f"Cannot open image: {e}")
        pause()
        return

    print()
    print(f"  {C.G}Format   {C.W}: {img.format}")
    print(f"  {C.G}Mode     {C.W}: {img.mode}")
    print(f"  {C.G}Size     {C.W}: {img.size[0]} x {img.size[1]} px")

    exif = img.getexif()
    if not exif:
        info("No EXIF metadata found.")
        pause()
        return

    info("EXIF metadata:")
    gps = {}
    for tag_id, value in exif.items():
        tag = TAGS.get(tag_id, tag_id)
        if tag == "GPSInfo":
            for t in value:
                gps[GPSTAGS.get(t, t)] = value[t]
        else:
            print(f"  {C.G}{tag:<22}{C.W}: {value}")

    if gps:
        info("GPS data:")
        for k, v in gps.items():
            print(f"  {C.G}{k:<22}{C.W}: {v}")
        try:
            lat = _dms_to_deg(gps["GPSLatitude"])
            lon = _dms_to_deg(gps["GPSLongitude"])
            if gps.get("GPSLatitudeRef") == "S":
                lat = -lat
            if gps.get("GPSLongitudeRef") == "W":
                lon = -lon
            print(f"\n  {C.G}Coordinates {C.W}: {lat:.6f}, {lon:.6f}")
            print(f"  {C.G}Map         {C.W}: https://www.google.com/maps?q={lat},{lon}")
        except Exception:
            warn("Could not decode GPS coordinates.")
    pause()


# ---------------------------------------------------------------------------
# 6. Wi-Fi Tracer (BSSID geolocation)
# ---------------------------------------------------------------------------
def wifi_tracer():
    header("Wi-Fi Tracer")
    info("Wi-Fi geolocation works off the AP MAC address (BSSID).")

    bssid = ask("BSSID / MAC (e.g. 00:11:22:33:44:55), blank = scan local: ")

    if not bssid:
        system = platform.system().lower()
        try:
            if system == "windows":
                out = subprocess.check_output(["netsh", "wlan", "show", "bssid"],
                                              text=True, stderr=subprocess.DEVNULL)
                print(out)
            elif system == "linux":
                out = subprocess.check_output(["nmcli", "-f", "BSSID,SSID", "dev", "wifi"],
                                              text=True, stderr=subprocess.DEVNULL)
                print(out)
            elif system == "darwin":
                out = subprocess.check_output(
                    ["/System/Library/PrivateFrameworks/Apple80211.framework/"
                     "Versions/Current/Resources/airport", "-s"],
                    text=True, stderr=subprocess.DEVNULL)
                print(out)
            else:
                warn("Unsupported OS for local scan.")
                pause()
                return
        except Exception as e:
            err(f"Local scan failed: {e}")
            info("Try: nmcli dev wifi  |  netsh wlan show networks mode=bssid")
            pause()
            return
        bssid = ask("Now enter the BSSID to trace: ")

    if not bssid:
        warn("No BSSID given.")
        pause()
        return

    payload = {"wifiAccessPoints": [{"macAddress": bssid}]}
    if not HAVE_REQUESTS:
        err("requests not installed.")
        pause()
        return

    try:
        r = requests.post(
            "https://www.googleapis.com/geolocation/v1/geolocate",
            json={"considerIp": True},  # key required for BSSID accuracy
            timeout=10)
        info("Google Geolocation API requires an API key for BSSID lookups.")
    except Exception:
        pass

    # Keyless alternative: Mozilla Location Service (retired for new keys),
    # so fall back to a manual coordinate plot prompt.
    print()
    print(f"  {C.G}BSSID       {C.W}: {bssid}")
    info("For keyless results, use https://wigle.net (free account, BSSID search).")
    print(f"  {C.G}›{C.W} https://wigle.net/search#searchBssid={bssid.replace(':', '')}")
    pause()


# ---------------------------------------------------------------------------
# 7. WhatsApp Tracer
# ---------------------------------------------------------------------------
def whatsapp_tracer():
    header("WhatsApp Tracer")
    num = ask("Phone number in international format (e.g. +420123456789): ")
    if not num:
        warn("Empty input.")
        return

    digits = num.replace("+", "").replace(" ", "").replace("-", "")
    print()
    print(f"  {C.G}Chat link   {C.W}: https://wa.me/{digits}")
    print(f"  {C.G}API link    {C.W}: https://api.whatsapp.com/send?phone={digits}")
    print(f"  {C.G}QR image    {C.W}: https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=https://wa.me/{digits}")

    data = get_json(f"https://wa.me/{digits}")  # not JSON; informational only
    info("wa.me returns an HTML page; open the link to confirm the account exists.")
    info("If the profile loads with a photo/name, the number is registered.")
    pause()


# ---------------------------------------------------------------------------
# 8. DIS Trac  (Discord server / invite intel)
# ---------------------------------------------------------------------------
def dis_trac():
    header("DIS Trac  (Discord)")
    inv = ask("Discord invite code or full invite URL: ")
    if not inv:
        warn("Empty input.")
        return

    code = inv.rstrip("/").split("/")[-1]
    data = get_json(f"https://discord.com/api/v10/invites/{code}?with_counts=true")
    if not data:
        pause()
        return

    if "guild" not in data:
        err(data.get("message", "Invalid or expired invite."))
        pause()
        return

    g = data["guild"]
    print()
    print(f"  {C.G}Server name {C.W}: {g.get('name')}")
    print(f"  {C.G}Server ID   {C.W}: {g.get('id')}")
    print(f"  {C.G}Members     {C.W}: {data.get('approximate_member_count')}")
    print(f"  {C.G}Online      {C.W}: {data.get('approximate_presence_count')}")
    if g.get("icon"):
        print(f"  {C.G}Icon        {C.W}: https://cdn.discordapp.com/icons/{g['id']}/{g['icon']}.png")
    if g.get("description"):
        print(f"  {C.G}Description {C.W}: {g['description']}")
    pause()


# ---------------------------------------------------------------------------
# 9. Auto All Trac
# ---------------------------------------------------------------------------
def auto_all():
    header("Auto All Trac")
    warn("Auto mode runs module 1-8 inputs interactively.")
    target = ask("Primary target (name / handle / IP / phone / invite): ")
    if not target:
        warn("Empty input.")
        return

    info(f"Running best-effort lookup on: {target}")

    # IP
    if any(c.isdigit() for c in target) and "." in target:
        d = get_json(f"http://ip-api.com/json/{target}")
        if d and d.get("status") == "success":
            ok(f"Looks like an IP -> {d.get('city')}, {d.get('country')} | ISP {d.get('isp')}")

    # Phone
    if target.startswith("+") and HAVE_PHONE:
        try:
            p = phonenumbers.parse(target, None)
            ok(f"Phone -> {geocoder.description_for_number(p, 'en')} | "
               f"{carrier.name_for_number(p, 'en')}")
        except Exception:
            pass

    # Discord invite
    if "discord.gg" in target or "discord.com/invite" in target:
        code = target.rstrip("/").split("/")[-1]
        d = get_json(f"https://discord.com/api/v10/invites/{code}?with_counts=true")
        if d and "guild" in d:
            ok(f"Discord guild -> {d['guild'].get('name')} "
               f"({d.get('approximate_member_count')} members)")

    # Name / generic -> search links
    print(f"\n  {C.G}›{C.W} https://www.google.com/search?q=%22{target}%22")
    print(f"  {C.G}›{C.W} https://www.bing.com/search?q=%22{target}%22")
    print(f"  {C.G}›{C.W} https://github.com/search?q={target}")
    pause()


# ---------------------------------------------------------------------------
# 10. Admin Join
# ---------------------------------------------------------------------------
def admin_join():
    header("Admin Join")
    code = ask("Enter admin code: ")
    if code == ADMIN_CODE:
        ok("Access granted. Welcome, admin.")
        info("Admin panel:")
        print(f"  {C.G}›{C.W} Modules unlocked : all")
        print(f"  {C.G}›{C.W} Version          : {VERSION}")
        print(f"  {C.G}›{C.W} Config path      : {os.path.abspath(__file__)}")
        print(f"  {C.G}›{C.W} Log dir          : {os.path.join(os.getcwd(), 'logs')}")
    else:
        err("Wrong code. Access denied.")
    pause()


# ---------------------------------------------------------------------------
# 11. Update
# ---------------------------------------------------------------------------
def update():
    header("Update")
    info("Checking for updates...")
    time.sleep(1)

    remote = None
    if HAVE_REQUESTS:
        try:
            r = requests.get(
                "https://raw.githubusercontent.com/injektor/osintx/main/version.txt",
                timeout=6)
            if r.status_code == 200:
                remote = r.text.strip()
        except Exception:
            remote = None

    if remote:
        if remote != VERSION:
            ok(f"New version available: {remote} (you have {VERSION})")
        else:
            ok("You are on the latest version.")
    else:
        warn("Update server unreachable (no repo configured).")
        info("Edit the URL in update() to point at your own release feed.")
    pause()


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
ACTIONS = {
    "1": name_tracer,
    "2": phone_tracer,
    "3": ip_lookup,
    "4": discord_nick,
    "5": foto_analyzer,
    "6": wifi_tracer,
    "7": whatsapp_tracer,
    "8": dis_trac,
    "9": auto_all,
    "10": admin_join,
    "11": update,
    "12": None,
}


def main():
    while True:
        clear()
        print(f"{C.M}{BANNER}{C.RESET}")
        print(f"{C.CY}{C.BOLD}            OsintX  ·  OSINT Toolkit  ·  by Injektor{C.RESET}")
        print(MENU)

        choice = ask("OsintX > ")

        if choice == "12" or choice.lower() in ("exit", "quit", "q"):
            print(f"\n{C.G}[+] Goodbye. Stay ethical.{C.RESET}\n")
            sys.exit(0)

        action = ACTIONS.get(choice)
        if action:
            try:
                action()
            except KeyboardInterrupt:
                print(f"\n{C.Y}[!] Interrupted.{C.RESET}")
                time.sleep(1)
        else:
            warn("Invalid option. Choose 1-12.")
            time.sleep(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.G}[+] Exited.{C.RESET}\n")
