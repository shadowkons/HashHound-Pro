<p align="center">
  <img src="Assets/logo1.png" style="width: 100%; max-width: 800px; height: auto;" alt="HashHound Pro Logo">
</p>

# 🐕‍🦺 HashHound Pro v1.0 – Hash Finder + Auto Cracker

🔎 **Advanced Cryptographic Identification & Auto-Cracking Suite**

HashHound Pro is a high-performance, modular Python utility built for security researchers and CTF players. It instantly generates, identifies, and categorizes over 80 hash formats and 20 encodings, seamlessly bridging the gap between identification and plaintext recovery via live Hashcat integration.

---

## 📌 Table of Contents

> - [Features](#-features)
> - [Installation](#-installation)
> - [Usage](#-usage)
> - [Screenshots](#-screenshots)
> - [Analysis & Output](#-analysis--output)
> - [Technologies Used](#-technologies-used)
> - [Future Enhancements](#-future-enhancements)
> - [Disclaimer](#-legal-disclaimer)
> - [Author](#-author)
> - [Support](#-support--contribution)

---

## 🔍 Features

> 🚀 **Massive Hash Lexicon** – Automatically detects and analyzes 80+ cryptographic hashes (MD5, SHA families, NTLM, Bcrypt, Argon2, etc.) and 20+ encodings.
> 
> 🧠 **Automated Hashcat Integration** – Maps identified algorithms directly to their specific Hashcat module (`-m` flag) and dynamically generates the cracking command.
> 
> 🕸️ **Advanced Attack Vectors** – Execute Wordlist, Rule-based, or Mask (brute-force) attacks directly from the HashHound terminal.
> 
> 🛡️ **Smart Encoding Recovery** – Automatically detects missing padding in Base64 strings, corrects it on the fly, decodes the ciphertext, and translates ROT13.
> 
> ⚡ **Zero External Python Dependencies** – Built entirely using Python's standard library. No bloated `pip install` requirements needed.
> 
> 📊 **Batch File Processing** – Ingest a `.txt` file of multiple hashes to generate a clean, highly readable visual table for batch processing and automated recovery.

---

## 🛠️ Installation

> ### 📥 1. Clone the Repository
> **Linux / macOS / Windows**
> ```bash
> git clone [https://github.com/shadowkons/HashHound-Pro.git](https://github.com/shadowkons/HashHound-Pro.git)
> cd HashHound-Pro
> ```
> 
> ### 📦 2. System Requirements
> HashHound Pro runs natively on Python 3 Standard Libraries (no `requirements.txt` necessary). However, the auto-cracking features require **Hashcat** to be installed on your host system.
> 
> **Debian / Kali / Ubuntu:**
> ```bash
> sudo apt update
> sudo apt install hashcat
> ```
> 
> *Note: HashHound Pro checks standard Kali Linux paths (e.g., `/usr/share/wordlists/rockyou.txt` and `/usr/share/hashcat/rules/`) by default, but allows custom path inputs for macOS/Windows users.*

---

## 💻 Usage

> Run HashHound Pro directly from your terminal. The tool utilizes an interactive configuration prompt.
> 
> ```bash
> python3 hashhound.py
> ```
> 
> ### 🖱️ Main Menu Modules
> Upon launch, you will be presented with two primary modules:
> - **[1] Hash Generator:** Input any plaintext word to instantly generate its equivalent across dozens of cryptographic algorithms and encodings.
> - **[2] Hash Finder + Auto Crack:** Input a raw hash string or provide a file path (e.g., `hashes.txt`). The engine will classify the data and guide you through the Hashcat attack setup.

---

## 🖼 Screenshots

> 🔴 **HashHound Pro Startup & Analysis**
> *(Signature ASCII banner and format identification table)*
> <img width="977" height="468" alt="Interface Screenshot" src="https://placeholder-link-to-your-image.com/1.png" />
> 
> 🔴 **Live Hashcat Execution**
> *(Subprocess bridge executing a local dictionary attack)*
> <img width="1054" height="360" alt="Cracking Screenshot" src="https://placeholder-link-to-your-image.com/2.png" />

---

## 🗂 Analysis & Output

> HashHound Pro generates clean console outputs and automated save files to prevent data loss during analysis.
> 
> | Output Type | Description |
> | :--- | :--- |
> | 📜 **Generation Reports** | Saves `hashes_[plaintext]_[timestamp].txt` containing all computed hash variants for easy archiving. |
> | 📊 **Batch Processing Table** | Neatly organizes ingested `.txt` files into an interactive ID-based grid, categorizing each string by Type, Category, and Entropy. |
> | 🔑 **Plaintext Extraction** | Extracts and strictly isolates recovered passwords in high-visibility RED formatting after successful Hashcat runs. |

---

## 🧩 Technologies Used

> - 🐍 **Python 3.x** – Core programming language.
> - ⚙️ **Subprocess/OS** – For terminal bridging and secure Hashcat execution.
> - 🧩 **Re (Regex)** – For high-speed pattern recognition across 100+ signatures.
> - 🧮 **Math** – For calculating string entropy to detect unknown encryptions.
> - 🛠️ **Hashcat** – Industry-standard advanced password recovery utility.

---

## 🔮 Future Enhancements

> - ⚙️ **Custom Hashcat Tuning** – Option to add custom flags or workload profiles from within the HashHound prompt.
> - 🥷 **API Integration** – Auto-check hashes against public databases (like CrackStation) before utilizing local GPU power.
> - 🌍 **Extended Encodings** – Support for Hex, Binary, Morse, and URL decoding in the batch processor.

---

## ⚠ Legal Disclaimer

> 🚨 **IMPORTANT – READ BEFORE USING**
> 
> HashHound Pro is intended only for **EDUCATIONAL, ACADEMIC GROWTH, and AUTHORIZED SECURITY TESTING**.
> 
> ### ✅ Allowed Uses
> - Solving Capture The Flag (CTF) challenges in lab environments.
> - Security testing on systems you own.
> - Authorized penetration testing with explicit written permission.
> 
> ### 🚫 Prohibited Uses
> - Unauthorized password cracking or testing of third-party hashes.
> - Illegal hacking or unauthorized access attempts.
> - Using HashHound Pro for malicious purposes.
> 
> ### ❗ Liability Disclaimer
> The author and contributors are **NOT** responsible for:
> - ❌ Illegal usage or misuse of this tool.
> - ❌ System degradation due to intensive Hashcat GPU usage.
> - ❌ Legal consequences or prosecution.
> 
> 🧠 *This tool is provided "AS IS" with no warranty, express or implied.*
> 🛡 *By using HashHound Pro, you acknowledge and accept full responsibility for your actions and agree to act ethically and legally.*

---

## 👨‍💻 Author

> **Abhilash**
> - 🐙 GitHub: [shadowkons](https://github.com/shadowkons)
> - 💼 LinkedIn: www.linkedin.com/in/abhilash-salim-9239b6343

---

## ⭐ Support & Contribution

> If you find this project helpful:
> - ⭐ **Star the repository** – Show your appreciation!
> - 🤝 **Contribute** – Submit pull requests with new Regex patterns or Hashcat `-m` codes.
> - 🐛 **Report bugs** – Open issues for any unrecognized hashes.
> 
> ### 📝 License
> This project operates under the **MIT License**. Please see the repository for details.

---

<p align="center">🙏 <b>Thank You for Using HashHound Pro!</b><br>Happy cracking and stay secure! 🔒</p>
