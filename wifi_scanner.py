#!/usr/bin/env python3
import os
import re
import csv
import time
import signal
import subprocess
from datetime import datetime
from collections import Counter, defaultdict

# PDF & charts
import matplotlib
matplotlib.use("Agg")  # headless
import matplotlib.pyplot as plt
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image as RLImage
from reportlab.lib.styles import getSampleStyleSheet

# --------------------
# Configuration
# --------------------
BASE_DIR = "/home/dheeraj/Documents/PROJECTS/Wi-Fi Security Analysis/wifi_logs"
REFRESH_SEC = 3  # live table refresh
AIRO_BANDS = ["bg"]  # change to ["abg"] if you want 2.4+5GHz (requires adapter support)

# globals
running = True
airodump_proc = None
interface_used = None
output_dir = None
csv_path = None


# --------------------
# Interface helpers
# --------------------
def run_cmd(cmd, check=False, shell=False):
    return subprocess.run(cmd, check=check, shell=shell,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

def detect_interfaces_iwdev():
    out = run_cmd(["iw", "dev"]).stdout
    return re.findall(r"Interface\s+([^\s]+)", out)

def detect_interfaces_iwconfig():
    out = run_cmd("iwconfig 2>/dev/null", shell=True).stdout
    return re.findall(r"^([^\s]+)\s+IEEE\s+802\.11", out, re.MULTILINE)

def get_wifi_interface():
    """
    Pick a Wi-Fi interface automatically.
    Preference order:
      1) Any interface already in monitor mode
      2) First wireless interface found by iw dev
      3) Fallback to iwconfig
    """
    # Already monitor?
    out = run_cmd(["iw", "dev"]).stdout
    blocks = re.split(r"\n(?=Interface\s)", out.strip())
    for blk in blocks:
        if "type monitor" in blk:
            m = re.search(r"Interface\s+([^\s]+)", blk)
            if m: 
                return m.group(1)

    # Otherwise normal wireless interface
    devs = detect_interfaces_iwdev()
    if devs:
        return devs[0]

    cfg = detect_interfaces_iwconfig()
    if cfg:
        return cfg[0]

    return None

def enable_monitor_mode(iface):
    # If already monitor, do nothing
    out = run_cmd(["iw", "dev"]).stdout
    for blk in re.split(r"\n(?=Interface\s)", out.strip()):
        if f"Interface {iface}" in blk and "type monitor" in blk:
            print(f"✅ {iface} already in monitor mode")
            return iface

    print(f"⚙️ Enabling monitor mode on {iface}...")
    # Bring down → set type monitor → up
    run_cmd(["sudo", "ip", "link", "set", iface, "down"])
    # Some drivers require "iw <iface> set monitor none"; most accept "set type monitor"
    res = run_cmd(["sudo", "iw", iface, "set", "type", "monitor"])
    if res.returncode != 0:
        # fallback
        run_cmd(["sudo", "iw", iface, "set", "monitor", "none"])
    run_cmd(["sudo", "ip", "link", "set", iface, "up"])
    print(f"✅ Monitor mode enabled on {iface}")
    return iface

def disable_monitor_mode(iface):
    # If iface disappeared or already managed, best-effort restore
    print(f"🔄 Restoring managed mode on {iface}...")
    run_cmd(["sudo", "ip", "link", "set", iface, "down"])
    run_cmd(["sudo", "iw", iface, "set", "type", "managed"])
    run_cmd(["sudo", "ip", "link", "set", iface, "up"])
    print(f"✅ Managed mode restored on {iface}")


# --------------------
# Airodump helpers
# --------------------
def start_airodump(iface, out_prefix):
    global airodump_proc
    cmd = ["sudo", "airodump-ng", "-w", out_prefix, "--output-format", "csv", iface]
    # Add band flags if requested
    for band in AIRO_BANDS:
        cmd.extend(["--band", band])
    # Start in its own process group so we can kill it cleanly
    airodump_proc = subprocess.Popen(
        cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setsid
    )
    time.sleep(2)  # let file appear

def stop_airodump():
    global airodump_proc
    if airodump_proc is not None:
        try:
            os.killpg(os.getpgid(airodump_proc.pid), signal.SIGTERM)
        except Exception:
            pass
        airodump_proc = None


# --------------------
# CSV parsing (AP section only)
# --------------------
def parse_airodump_csv(ap_csv_path):
    """
    Returns list of dicts with keys: BSSID, SSID, Channel, Privacy, Cipher, Auth, Power
    Reads ONLY the AP table (stops at 'Station MAC').
    """
    nets = []
    if not (ap_csv_path and os.path.exists(ap_csv_path)):
        return nets

    try:
        with open(ap_csv_path, newline="", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)
            ap_header_seen = False
            for row in reader:
                if not row:
                    continue
                first = row[0].strip()
                if first == "BSSID":
                    ap_header_seen = True
                    continue
                if first == "Station MAC":
                    break
                if ap_header_seen and len(row) > 13:
                    # airolib headers (common):
                    # 0 BSSID, 1 First time seen, 2 Last time seen, 3 channel, 4 Speed, 5 Privacy,
                    # 6 Cipher, 7 Authentication, 8 Power, 9 beacons, 10 #IV, 11 LAN IP,
                    # 12 ID-length, 13 ESSID, 14 Key
                    bssid = row[0].strip()
                    ch    = row[3].strip()
                    priv  = row[5].strip()
                    cipher= row[6].strip()
                    auth  = row[7].strip()
                    pwr   = row[8].strip()
                    essid = row[13].strip() or "Hidden"
                    nets.append({
                        "BSSID": bssid,
                        "SSID": essid,
                        "Channel": ch,
                        "Privacy": priv,
                        "Cipher": cipher,
                        "Auth": auth,
                        "Power": pwr
                    })
    except Exception:
        pass
    return nets


# --------------------
# Live terminal view
# --------------------
def print_live_table(networks):
    os.system("clear")
    print("📡 Live Wi-Fi Scan Results\n")
    print("{:<20} {:<28} {:<7} {:<8} {:<7} {:<5}".format("BSSID", "SSID", "CH", "Privacy", "Auth", "PWR"))
    print("-" * 80)
    for n in networks[:80]:  # keep terminal readable
        print("{:<20} {:<28} {:<7} {:<8} {:<7} {:<5}".format(
            n["BSSID"], n["SSID"][:28], n["Channel"], n["Privacy"], n["Auth"], n["Power"]
        ))
    print("\nPress CTRL+C to stop & generate PDF report.")


# --------------------
# Charts & PDF
# --------------------
def save_charts(networks, folder):
    # Channel distribution
    ch_vals = []
    for n in networks:
        try:
            ch_vals.append(int(str(n["Channel"]).strip()))
        except Exception:
            continue
    channel_img = None
    if ch_vals:
        plt.figure(figsize=(6, 4))
        plt.hist(ch_vals, bins=range(1, max(ch_vals)+2), align="left", rwidth=0.8)
        plt.title("Channel Distribution")
        plt.xlabel("Channel")
        plt.ylabel("Count")
        channel_img = os.path.join(folder, "channel_distribution.png")
        plt.savefig(channel_img, bbox_inches="tight")
        plt.close()

    # Encryption (Privacy) distribution
    priv_counts = Counter([n["Privacy"] for n in networks if n.get("Privacy")])
    enc_img = None
    if priv_counts:
        plt.figure(figsize=(6, 4))
        plt.pie(list(priv_counts.values()), labels=list(priv_counts.keys()), autopct="%1.1f%%", startangle=140)
        plt.title("Encryption Types (Privacy)")
        enc_img = os.path.join(folder, "encryption_types.png")
        plt.savefig(enc_img, bbox_inches="tight")
        plt.close()

    return channel_img, enc_img

def generate_pdf(networks, folder, iface):
    pdf_path = os.path.join(folder, "wifi_report.pdf")
    doc = SimpleDocTemplate(pdf_path, pagesize=A4)
    styles = getSampleStyleSheet()
    elems = []

    # Title & meta
    elems.append(Paragraph("📡 Wi-Fi Security Analysis Report", styles["Title"]))
    elems.append(Spacer(1, 6))
    meta = f"Interface: {iface} &nbsp;&nbsp;|&nbsp;&nbsp; Scan time: {datetime.now().strftime('%d-%m-%Y %I:%M %p')}"
    elems.append(Paragraph(meta, styles["Normal"]))
    elems.append(Spacer(1, 12))

    # Table
    data = [["BSSID", "SSID", "CH", "Privacy", "Cipher", "Auth", "PWR"]]
    for n in networks:
        data.append([n["BSSID"], n["SSID"], n["Channel"], n["Privacy"], n["Cipher"], n["Auth"], n["Power"]])

    table = Table(data, repeatRows=1, colWidths=[100, 150, 30, 60, 60, 50, 30])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightblue),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
    ]))
    elems.append(table)
    elems.append(Spacer(1, 16))

    # Charts
    ch_img, enc_img = save_charts(networks, folder)
    if ch_img:
        elems.append(Paragraph("📊 Channel Distribution", styles["Heading2"]))
        elems.append(RLImage(ch_img, width=420, height=280))
        elems.append(Spacer(1, 12))
    if enc_img:
        elems.append(Paragraph("🔒 Encryption Types", styles["Heading2"]))
        elems.append(RLImage(enc_img, width=420, height=280))
        elems.append(Spacer(1, 12))

    doc.build(elems)
    print(f"✅ PDF report saved: {pdf_path}")


# --------------------
# Signal handling
# --------------------
def on_sigint(sig, frame):
    global running
    running = False
    print("\n🛑 Stopping scan… Generating report…")


# --------------------
# Main
# --------------------
def main():
    global running, interface_used, output_dir, csv_path

    # Prepare folders
    date_folder = datetime.now().strftime("%d-%m-%Y")
    time_folder = datetime.now().strftime("%I:%M %p")
    output_dir = os.path.join(BASE_DIR, date_folder, time_folder)
    os.makedirs(output_dir, exist_ok=True)
    out_prefix = os.path.join(output_dir, "scan")

    # Detect + set monitor
    iface = get_wifi_interface()
    if not iface:
        print("❌ No Wi-Fi interface found.")
        return
    interface_used = enable_monitor_mode(iface)

    # Start airodump
    start_airodump(interface_used, out_prefix)
    csv_path = out_prefix + "-01.csv"

    print(f"🔍 Scanning on {interface_used}… Results will be saved in:\n   {output_dir}")
    signal.signal(signal.SIGINT, on_sigint)

    try:
        while running:
            if os.path.exists(csv_path):
                nets = parse_airodump_csv(csv_path)
                if nets:
                    print_live_table(nets)
            time.sleep(REFRESH_SEC)
    finally:
        # Cleanup / finalize
        stop_airodump()
        try:
            if os.path.exists(csv_path):
                nets = parse_airodump_csv(csv_path)
                if nets:
                    generate_pdf(nets, output_dir, interface_used)
                else:
                    print("ℹ️ No networks captured; PDF not generated.")
        except Exception as e:
            print(f"⚠️ Failed to generate PDF: {e}")
        # Always try to restore managed mode
        try:
            disable_monitor_mode(interface_used)
        except Exception:
            pass
        print("✅ Done.")


if __name__ == "__main__":
    # Ensure base directory exists
    os.makedirs(BASE_DIR, exist_ok=True)
    main()
