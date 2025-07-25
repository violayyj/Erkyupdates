import tkinter as tk
from tkinter import font as tkfont, scrolledtext, filedialog
import phonenumbers
from phonenumbers import carrier, geocoder
import requests
import subprocess
import sys
import os

CURRENT_VERSION = "beta 1.0.1"
UPDATE_VERSION_URL = "https://raw.githubusercontent.com/violayyj/Erkyupdates/main/erky_version.txt"
UPDATE_SCRIPT_URL = "https://raw.githubusercontent.com/violayyj/Erkyupdates/main/erky.py"
SCRIPT_PATH = os.path.realpath(__file__)

def show_intro(callback):
    intro = tk.Tk()
    intro.title("Erky Boot")
    intro.configure(bg="black")
    intro.attributes("-fullscreen", True)
    canvas = tk.Canvas(intro, bg="black", highlightthickness=0)
    canvas.pack(fill="both", expand=True)
    width = intro.winfo_screenwidth()
    height = intro.winfo_screenheight()
    glow_color = "#7B3FBF"
    for glow_radius in range(200, 270, 10):
        canvas.create_oval(
            width//2 - glow_radius, height//2 - glow_radius,
            width//2 + glow_radius, height//2 + glow_radius,
            outline=glow_color, width=2, stipple="gray25"
        )
    points = [
        width//2, height//2 - 80,
        width//2 - 100, height//2 + 70,
        width//2 + 100, height//2 + 70
    ]
    canvas.create_polygon(points, fill="#5D3A85", outline="#A066FF", width=3)
    eye_radius = 15
    eye_y = height//2 - 20
    eye_x_offset = 40
    canvas.create_oval(width//2 - eye_x_offset - eye_radius, eye_y - eye_radius,
                       width//2 - eye_x_offset + eye_radius, eye_y + eye_radius,
                       fill="#A066FF", outline="#D1A3FF", width=2)
    canvas.create_oval(width//2 + eye_x_offset - eye_radius, eye_y - eye_radius,
                       width//2 + eye_x_offset + eye_radius, eye_y + eye_radius,
                       fill="#A066FF", outline="#D1A3FF", width=2)
    container = tk.Frame(intro, bg="black")
    container.place(relx=0.5, rely=0.65, anchor="center")
    neon_purple = "#A066FF"
    label = tk.Label(container, text="ERKY OSINT TOOL BY VIOLA", fg=neon_purple, bg="black", font=("Consolas", 36, "bold"))
    label.pack(pady=(0, 40))
    loading_frame = tk.Frame(container, bg="black")
    loading_frame.pack()
    loading_bar = tk.Canvas(loading_frame, width=600, height=30, bg="gray25", highlightthickness=0)
    loading_bar.pack()
    fill = loading_bar.create_rectangle(0, 0, 0, 30, fill=neon_purple, width=0)

    def animate(i=0):
        if i >= 600:
            intro.destroy()
            callback()
            return
        loading_bar.coords(fill, 0, 0, i, 30)
        brightness = 170 + int(85 * (i / 600))
        color = f"#A0{brightness:02X}FF"
        loading_bar.itemconfig(fill, fill=color)
        intro.after(12, animate, i + 5)

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

def open_notes_window():
    notes_win = tk.Toplevel()
    notes_win.title("Erky Notes")
    notes_win.geometry("600x500")
    notes_win.configure(bg="black")
    text_area = scrolledtext.ScrolledText(notes_win, wrap=tk.WORD, bg="black", fg="#5D3A85", insertbackground="#5D3A85",
                                          font=("Consolas", 12))
    text_area.pack(expand=True, fill="both", padx=10, pady=10)

    def save_note():
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if file_path:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(text_area.get("1.0", tk.END).strip())

    def clear_note():
        text_area.delete("1.0", tk.END)

    btn_frame = tk.Frame(notes_win, bg="black")
    btn_frame.pack(pady=5)
    tk.Button(btn_frame, text="Save", command=save_note, bg="#D1A3FF", fg="#5D3A85", width=15).pack(side="left", padx=10)
    tk.Button(btn_frame, text="Clear", command=clear_note, bg="#D1A3FF", fg="#5D3A85", width=15).pack(side="right", padx=10)

def run_erky_gui():
    root = tk.Tk()
    root.title("ERKY beta 1.0.1")
    root.geometry("600x750")
    root.configure(bg="black")

    heading_font = tkfont.Font(family="Consolas", size=18, weight="bold")
    text_font = tkfont.Font(family="Consolas", size=10)

    dark_purple = "#5D3A85"
    neon_purple = "#A066FF"
    light_purple = "#D1A3FF"
    lime = "lime"

    title_label = tk.Label(root, text="ERKY beta 1.0.1", fg=neon_purple, bg="black", font=("Consolas", 24, "bold"))
    title_label.pack(pady=(10, 0))

    subtitle_label = tk.Label(root, text="made by viola", fg=neon_purple, bg="black", font=("Consolas", 14))
    subtitle_label.pack(pady=(0, 5))

    canvas = tk.Canvas(root, bg="black", highlightthickness=0)
    scrollbar = tk.Scrollbar(root, orient="vertical", command=canvas.yview)
    scroll_frame = tk.Frame(canvas, bg="black")

    def on_mousewheel(event):
        canvas.yview_scroll(-1 * int(event.delta / 120), "units")

    canvas.bind_all("<MouseWheel>", on_mousewheel)
    scroll_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
    canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)
    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    info_label = tk.Label(scroll_frame, text="Infos Output", fg=neon_purple, bg="black", font=heading_font)
    info_label.pack(pady=(10, 5))

    info_text = scrolledtext.ScrolledText(scroll_frame, width=65, height=20, wrap=tk.WORD, font=text_font,
                                          bg="black", fg=lime, state='disabled')
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

    def copy_output():
        root.clipboard_clear()
        root.clipboard_append(info_text.get(1.0, tk.END).strip())
        root.update()

    tk.Label(scroll_frame, text="Phone Num, Domain or IP:", fg=neon_purple, bg="black", font=heading_font).pack(pady=10)
    entry = tk.Entry(scroll_frame, font=text_font, width=45, bg=light_purple, fg=dark_purple, insertbackground=dark_purple, relief="flat")
    entry.pack(pady=5, ipady=5)

    def create_button(text, command):
        return tk.Button(scroll_frame, text=text, command=command, bg=light_purple, fg=dark_purple,
                         activebackground=dark_purple, activeforeground=neon_purple, font=text_font, relief="raised", bd=3, width=35, height=2)

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

    def shorten_link():
        url = entry.get().strip()
        if not url:
            update_info_window("[Shortener] Please enter a URL.")
            return
        try:
            res = requests.get(f"https://is.gd/create.php?format=simple&url={url}", timeout=5)
            if res.status_code == 200:
                short_url = res.text.strip()
                update_info_window(f"[Shortener] Shortened URL:\n{short_url}")
            else:
                update_info_window("[Shortener] Failed to shorten URL.")
        except Exception as e:
            update_info_window(f"[Shortener] Error: {e}")

    def port_scan():
        target = entry.get().strip()
        if target:
            update_info_window(f"[Port Scan Preview] https://yougetsignal.com/tools/open-ports/?remoteAddress={target}")
        else:
            update_info_window("[Port Scan] Please enter a domain or IP.")

    def url_scan_preview():
        url = entry.get().strip()
        if url:
            update_info_window(f"[URL Scan Preview] https://urlscan.io/search/#domain:{url}")
        else:
            update_info_window("[URL Scan] Please enter a URL.")

    def reverse_ip_lookup():
        ip = entry.get().strip()
        if ip:
            update_info_window(f"[Reverse IP Lookup] https://viewdns.info/reverseip/?host={ip}")
        else:
            update_info_window("[Reverse IP Lookup] Please enter an IP.")

    def same_ip_domains():
        target = entry.get().strip()
        if target:
            update_info_window(f"[Domains on Same IP] https://dnslytics.com/reverse-ip/{target}")
        else:
            update_info_window("[Domains on Same IP] Please enter a domain.")

    def email_tracker():
        email = entry.get().strip()
        if not email:
            update_info_window("[Email Tracker] Please enter an email address.")
            return
        update_info_window(f"[Email Tracker] Checking breaches for: {email} ...")
        try:
            url = f"https://haveibeenpwned-api.com/api/v2/breachedaccount/{email}"
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                breaches = resp.json()
                if breaches:
                    update_info_window(f"[Email Tracker] Found {len(breaches)} breaches:")
                    for breach in breaches:
                        name = breach.get("Name", "N/A")
                        domain = breach.get("Domain", "N/A")
                        date = breach.get("BreachDate", "N/A")
                        update_info_window(f" - {name} ({domain}), breached on {date}")
                else:
                    update_info_window("[Email Tracker] No breaches found.")
            elif resp.status_code == 404:
                update_info_window("[Email Tracker] No breaches found.")
            else:
                update_info_window(f"[Email Tracker] API Error: Status code {resp.status_code}")
        except Exception as e:
            update_info_window(f"[Email Tracker] Error: {e}")

    def instagram_info():
        username = entry.get().strip()
        if not username:
            update_info_window("[Instagram Info] Please enter an Instagram username.")
            return

        update_info_window(f"[Instagram Info] Searching Instagram info for: {username}")

        api_url = f"https://instagram.blanace.de/api/ig?username={username}"
        try:
            resp = requests.get(api_url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "ok":
                    user_data = data.get("user", {})
                    full_name = user_data.get("full_name", "N/A")
                    biography = user_data.get("biography", "N/A")
                    followers = user_data.get("followers", "N/A")
                    following = user_data.get("following", "N/A")
                    posts = user_data.get("posts", "N/A")
                    is_private = user_data.get("is_private", False)
                    profile_url = f"https://instagram.com/{username}"

                    update_info_window(f"Full Name: {full_name}")
                    update_info_window(f"Biography: {biography}")
                    update_info_window(f"Followers: {followers}")
                    update_info_window(f"Following: {following}")
                    update_info_window(f"Posts: {posts}")
                    update_info_window(f"Private Account: {'Yes' if is_private else 'No'}")
                    update_info_window(f"Profile URL: {profile_url}")
                else:
                    update_info_window(f"[Instagram Info] API response error or user not found.")
            else:
                update_info_window(f"[Instagram Info] Failed to fetch data (Status code: {resp.status_code}).")
        except Exception as e:
            update_info_window(f"[Instagram Info] Error: {e}")

    create_button("1. NumVerify (Phone Info)", phone_info_lookup).pack(pady=5)
    create_button("2. Whois Lookup (domain)", whois_lookup).pack(pady=5)
    create_button("3. IP Geolocalizer", ip_geolocation).pack(pady=5)
    create_button("4. Clear Output", clear_output).pack(pady=5)
    create_button("5. Nexfil (Username Profile Search)", nexfil_lookup).pack(pady=5)
    create_button("6. Domains on Same IP", same_ip_domains).pack(pady=5)
    create_button("7. Link Shortener", shorten_link).pack(pady=5)
    create_button("8. Copy Output", copy_output).pack(pady=5)
    create_button("9. Notes", open_notes_window).pack(pady=5)
    create_button("10. Port Scan Preview", port_scan).pack(pady=5)
    create_button("11. URL Scan Preview", url_scan_preview).pack(pady=5)
    create_button("12. Reverse IP Lookup", reverse_ip_lookup).pack(pady=5)
    create_button("13. Email Tracker", email_tracker).pack(pady=5)
    create_button("14. Instagram Info", instagram_info).pack(pady=5)
    create_button("15. Update", lambda: check_for_update_gui(update_info_window)).pack(pady=5)
    create_button("16. Exit", root.destroy).pack(pady=15)

    root.mainloop()

if __name__ == "__main__":
    show_intro(run_erky_gui)
