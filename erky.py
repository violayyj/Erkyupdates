import tkinter as tk
from tkinter import font as tkfont, scrolledtext
import phonenumbers
from phonenumbers import carrier, geocoder
import requests
import subprocess
import sys
import os

CURRENT_VERSION = "0.0.1"
UPDATE_VERSION_URL = "https://raw.githubusercontent.com/violayyj/Erkyupdates/main/erky_version.txt"
UPDATE_SCRIPT_URL = "https://raw.githubusercontent.com/violayyj/Erkyupdates/main/erky.py"
SCRIPT_PATH = os.path.realpath(__file__)

# Intro loading screen
def show_intro(callback):
    intro = tk.Tk()
    intro.title("Erky Boot")
    intro.configure(bg="black")
    intro.attributes("-fullscreen", True)

    label = tk.Label(intro, text=":: ERKY SYSTEM BOOTING UP ::", fg="white", bg="black", font=("Consolas", 28))
    label.pack(pady=60)

    loading_frame = tk.Frame(intro, bg="black")
    loading_frame.pack()

    loading_bar = tk.Canvas(loading_frame, width=600, height=30, bg="gray25", highlightthickness=0)
    loading_bar.pack()
    fill = loading_bar.create_rectangle(0, 0, 0, 30, fill="#00ffff", width=0)

    def animate(i=0):
        if i > 600:
            intro.destroy()
            callback()
            return
        loading_bar.coords(fill, 0, 0, i, 30)
        intro.after(15, animate, i + 5)

    animate()
    intro.mainloop()

def check_for_update_gui(update_info_window):
    try:
        response = requests.get(UPDATE_VERSION_URL, timeout=5)
        if response.status_code == 200:
            remote_version = response.text.strip()
            if remote_version > CURRENT_VERSION:
                update_info_window(f"Update found: {remote_version}. Downloading new version...")
                new_script = requests.get(UPDATE_SCRIPT_URL, timeout=10).text
                with open(SCRIPT_PATH, "w", encoding="utf-8") as f:
                    f.write(new_script)
                update_info_window("Update downloaded. Please restart the program.")
                sys.exit(0)
            else:
                update_info_window("No update found.")
        else:
            update_info_window("Could not check for updates.")
    except Exception as e:
        update_info_window(f"Update check failed: {e}")

def run_erky_gui():
    root = tk.Tk()
    root.title("Erky alpha 0.0.1")
    root.geometry("550x700")
    root.configure(bg="black")

    heading_font = tkfont.Font(family="Consolas", size=18, weight="bold")
    text_font = tkfont.Font(family="Consolas", size=10)

    title_label = tk.Label(root, text="ERKY alpha 0.0.1", fg="#00ffff", bg="black", font=("Consolas", 24, "bold"))
    title_label.pack(pady=(10, 5))

    canvas = tk.Canvas(root, bg="black", highlightthickness=0)
    scrollbar = tk.Scrollbar(root, orient="vertical", command=canvas.yview)
    scroll_frame = tk.Frame(canvas, bg="black")

    scroll_frame.bind(
        "<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
    )

    canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)

    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    info_label = tk.Label(scroll_frame, text="Infos Output", fg="white", bg="black", font=heading_font)
    info_label.pack(pady=(10, 5))

    info_text = scrolledtext.ScrolledText(scroll_frame, width=65, height=20, wrap=tk.WORD, font=text_font,
                                          bg="black", fg="lime", state='disabled')
    info_text.pack(pady=5)

    def update_info_window(text):
        info_text.configure(state='normal')
        info_text.insert(tk.END, text + "\n\n")
        info_text.see(tk.END)
        info_text.configure(state='disabled')

    def clear_output():
        info_text.configure(state='normal')
        info_text.delete(1.0, tk.END)
        info_text.configure(state='disabled')

    tk.Label(scroll_frame, text="Phone Num, Domain or IP:", fg="white", bg="black", font=heading_font).pack(pady=10)
    entry = tk.Entry(scroll_frame, font=text_font, width=45, bg="#1e1e1e", fg="white", insertbackground="white", relief="flat")
    entry.pack(pady=5, ipady=5)

    def create_button(text, command):
        return tk.Button(scroll_frame, text=text, command=command, bg="#111111", fg="#00ffff",
                         activebackground="#333333", activeforeground="#00ffff", font=text_font, relief="raised", bd=3, width=35, height=2)

    def phone_info_lookup():
        phone = entry.get().strip()
        if not phone:
            update_info_window("[Phone Info] Please enter a phone number.")
            return
        try:
            if not phone.startswith('+'):
                parsed = phonenumbers.parse(phone, "IT")
            else:
                parsed = phonenumbers.parse(phone, None)

            number_type = phonenumbers.number_type(parsed)
            if number_type == phonenumbers.PhoneNumberType.UNKNOWN:
                update_info_window("[Phone Info] Invalid or unknown phone number.")
                return

            carrier_name = carrier.name_for_number(parsed, "en") or "N/A"
            region = geocoder.description_for_number(parsed, "en") or "N/A"
            country_code = phonenumbers.region_code_for_number(parsed) or "N/A"
            area_code = f"+{parsed.country_code}" if parsed.country_code else "N/A"

            update_info_window(f"[Phone Info]\nCarrier: {carrier_name}\nRegion: {region}\nCountry Code: {country_code}\nArea Code: {area_code}")

        except Exception as e:
            update_info_window(f"[Phone Info] Error: {e}")

    def whois_lookup():
        domain = entry.get().strip()
        if not domain:
            update_info_window("[Whois Lookup] Please enter a domain.")
            return
        try:
            url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=at_demo_key&domainName={domain}&outputFormat=JSON"
            resp = requests.get(url, timeout=10)
            data = resp.json()

            if 'WhoisRecord' in data:
                record = data['WhoisRecord']
                registrant = record.get('registrant', {})
                update_info_window(f"[Whois Lookup] Domain: {domain}")
                update_info_window(f"Registrar: {record.get('registrarName', 'N/A')}")
                update_info_window(f"Registrant: {registrant.get('name', 'N/A')}")
                update_info_window(f"Registrant Org: {registrant.get('organization', 'N/A')}")
                update_info_window(f"Creation Date: {record.get('createdDate', 'N/A')}")
                update_info_window(f"Expiration Date: {record.get('expiresDate', 'N/A')}")
            else:
                update_info_window(f"[Whois Lookup] No Whois info found for {domain}")
        except Exception as e:
            update_info_window(f"[Whois Lookup] Error: {e}")

    def ip_geolocation():
        ip = entry.get().strip()
        if not ip:
            update_info_window("[IP Geolocation] Please enter an IP address.")
            return
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10).json()
            if response.get("status") == "success":
                country = response.get("country", "N/A")
                region = response.get("regionName", "N/A")
                city = response.get("city", "N/A")
                lat = response.get("lat", "N/A")
                lon = response.get("lon", "N/A")
                timezone = response.get("timezone", "N/A")
                update_info_window(
                    f"[IP Geolocalizer] IP: {ip}\n"
                    f"Country: {country}\nRegion: {region}\nCity: {city}\n"
                    f"Latitude: {lat}\nLongitude: {lon}\nTimezone: {timezone}"
                )
            else:
                update_info_window(f"[IP Geolocalizer] Could not locate IP: {ip}")
        except Exception as e:
            update_info_window(f"[IP Geolocalizer] Error: {e}")

    def nexfil_lookup():
        user = entry.get().strip()
        if not user:
            update_info_window("[Nexfil] Please enter a username.")
            return
        update_info_window("Scanning in progress...")
        try:
            # Run nexfil subprocess; requires nexfil installed in environment
            result = subprocess.run(['nexfil', '-u', user], capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                output = result.stdout.strip()
                if output:
                    update_info_window("[Nexfil] Profiles found:\n" + output)
                else:
                    update_info_window("[Nexfil] No profiles found.")
            else:
                update_info_window(f"[Nexfil] Error: {result.stderr.strip()}")
        except subprocess.TimeoutExpired:
            update_info_window("[Nexfil] Timeout occurred.")
        except Exception as e:
            update_info_window(f"[Nexfil] Error: {e}")

    # Create buttons exactly as before, but add Update button
    create_button("1. NumVerify (Phone Info)", phone_info_lookup).pack(pady=5)
    create_button("2. Whois Lookup (domain)", whois_lookup).pack(pady=5)
    create_button("3. IP Geolocalizer", ip_geolocation).pack(pady=5)
    create_button("4. Clear Output", clear_output).pack(pady=5)
    create_button("5. Nexfil (Username Profile Search)", nexfil_lookup).pack(pady=5)
    create_button("6. Check for Update", lambda: check_for_update_gui(update_info_window)).pack(pady=5)
    create_button("7. Exit", root.destroy).pack(pady=15)

    root.mainloop()

if __name__ == "__main__":
    # Requires: pip install phonenumbers requests
    # Also requires nexfil installed and available in PATH
    show_intro(run_erky_gui)
