# 📡 Wi-Fi Security Analysis Tool

A Python-based tool that scans Wi-Fi networks in real-time, detects potential security vulnerabilities, and generates organized reports with graphs and tables. This tool automates Wi-Fi network analysis for penetration testers and network administrators.

---

## 🔑 Features

✔ Auto-detects Wi-Fi interface  
✔ Enables monitor mode automatically and restores it after the scan  
✔ Real-time scanning of nearby Wi-Fi networks with live terminal updates  
✔ Generates detailed PDF reports with:  
   - Table of networks with details (BSSID, SSID, Channel, Encryption, etc.)  
   - Channel distribution histogram  
   - Encryption type pie chart  
✔ Saves reports in structured folders by date and time  
✔ User-friendly interface with clear messages and error handling  

---

## 📂 Folder Structure

wifi_scanner/
├── wifi_scanner.py
├── requirements.txt
├── README.md
└── wifi_logs/
└── DD-MM-YYYY/
└── HH:MM AM/
├── scan-01.csv
├── wifi_report.pdf
├── channel_distribution.png
└── encryption_types.png


---

## ⚙ Installation

### 1. Clone the repository
..bash

git clone https://github.com/dheeraj05-22/WI-FI-SECURITY-ANALYSIS.git
cd WI-FI-SECURITY-ANALYSIS

### 2. Install dependencies
sudo apt update
sudo apt install python3-matplotlib python3-reportlab aircrack-ng -y

### (Optional: Create a Python virtual environment)
python3 -m venv venv
source venv/bin/activate
pip install matplotlib reportlab

###  🚀 Usage

Run the tool with sudo (required for interface manipulation):

sudo python3 wifi_scanner.py


The tool will:
✔ Detect the available Wi-Fi interface
✔ Enable monitor mode
✔ Start scanning and show live results in the terminal
✔ On pressing Ctrl+C, stop scanning and generate PDF reports

### 📦 Dependencies

Python 3.x

matplotlib for graphs

reportlab for PDF generation

aircrack-ng suite for Wi-Fi scanning

Linux environment with iw, ip, and airodump-ng available (tested on Kali Linux)

### 📖 Notes

Ensure no other tool is using the Wi-Fi interface while running the scanner.

Root privileges are required to change interface modes and access Wi-Fi scanning.

### 🤝 Contributing

Feel free to fork this project and submit pull requests. For improvements or bug reports, please open an issue on GitHub.

### 📫 Contact

For feedback, suggestions, or support, reach out at dheerajporeddy@gmail.com.

### 📜 License

This project is open source and free to use for learning, research, and network security assessments.


2. Paste it into the `nano` editor.

3. Replace these parts:
   - `https://github.com/yourusername/wifi_scanner.git` → with your actual GitHub repository link (we will set this up later if you don’t have it yet).
   - `your.email@example.com` → with your real email if you want.

4. Once done, save the file:
   - Press `Ctrl + O`, then Enter → saves the file.
   - Press `Ctrl + X` → exits nano.

---
