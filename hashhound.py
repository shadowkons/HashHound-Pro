#!/usr/bin/env python3
"""
HashHound Pro v1.0 — Hash Finder + Auto Cracking
- Menu: [1] Hash Generator | [2] Hash Finder + Auto Crack | [3] Exit
- Step 1: Identify hash type (80+ hashes, 20+ encodings)
- Step 2: Auto-launch Hashcat with Wordlist | Rule | Mask Attack
- Table-based output for file processing
"""

import re
import math
import time
import sys
import hashlib
import base64
import codecs
import subprocess
import os

# Windows ANSI color support
if os.name == 'nt':
    os.system('')

# Professional ANSI Colors
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    ORANGE = '\033[38;5;208m'

def print_startup_banner():
    banner = f"""{Colors.CYAN}{Colors.BOLD}
    ██╗  ██╗ █████╗ ███████╗██╗  ██╗██╗  ██╗██████╗ ██╗   ██╗███╗   ██╗██████╗ 
    ██║  ██║██╔══██╗██╔════╝██║  ██║██║  ██║██╔══██╗██║   ██║████╗  ██║██╔══██╗
    ███████║███████║███████╗███████║███████║██║  ██║██║   ██║██╔██╗ ██║██║  ██║
    ██╔══██║██╔══██║╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║╚██╗██║██║  ██║
    ██║  ██║██║  ██║███████║██║  ██║██║  ██║██████╔╝╚██████╔╝██║ ╚████║██████╔╝
    ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═════╝ {Colors.RESET}
    {Colors.BLUE}=========================================================================={Colors.RESET}
      {Colors.GREEN}>> HashHound Pro - Hash Finder + Auto Cracker <<{Colors.RESET}
    {Colors.BLUE}=========================================================================={Colors.RESET}
      {Colors.BOLD}Version{Colors.RESET} : {Colors.YELLOW}1.0{Colors.RESET}
      {Colors.BOLD}Author{Colors.RESET}  : {Colors.YELLOW}Abhilash{Colors.RESET}
      {Colors.BOLD}Features{Colors.RESET} : {Colors.CYAN}80+ Hashes | 20+ Encodings | Wordlist | Rule | Mask Attack{Colors.RESET}
    {Colors.BLUE}=========================================================================={Colors.RESET}
    """
    print(banner)
    
    sys.stdout.write(f"{Colors.MAGENTA}[*] Initializing HashHound Engine{Colors.RESET}")
    sys.stdout.flush()
    for _ in range(3):
        time.sleep(0.5)
        sys.stdout.write(f"{Colors.MAGENTA}.{Colors.RESET}")
        sys.stdout.flush()
    print(f"{Colors.GREEN} Ready!{Colors.RESET}\n")


# =============================================================================
# EXTENDED HASH PATTERN DATABASE — 80+ Hash Types
# =============================================================================
HASH_PATTERNS = {
    # --- MD Family ---
    "MD2": r"^[a-fA-F0-9]{32}$",
    "MD4": r"^[a-fA-F0-9]{32}$",
    "MD5": r"^[a-fA-F0-9]{32}$",
    "MD5 (Half)": r"^[a-fA-F0-9]{16}$",
    
    # --- SHA Family ---
    "SHA-0": r"^[a-fA-F0-9]{40}$",
    "SHA-1": r"^[a-fA-F0-9]{40}$",
    "SHA-224": r"^[a-fA-F0-9]{56}$",
    "SHA-256": r"^[a-fA-F0-9]{64}$",
    "SHA-384": r"^[a-fA-F0-9]{96}$",
    "SHA-512": r"^[a-fA-F0-9]{128}$",
    "SHA-512/224": r"^[a-fA-F0-9]{56}$",
    "SHA-512/256": r"^[a-fA-F0-9]{64}$",
    
    # --- SHA3 Family ---
    "SHA3-224": r"^[a-fA-F0-9]{56}$",
    "SHA3-256": r"^[a-fA-F0-9]{64}$",
    "SHA3-384": r"^[a-fA-F0-9]{96}$",
    "SHA3-512": r"^[a-fA-F0-9]{128}$",
    "SHAKE128 (32B)": r"^[a-fA-F0-9]{64}$",
    "SHAKE256 (64B)": r"^[a-fA-F0-9]{128}$",
    
    # --- RIPEMD Family ---
    "RIPEMD-128": r"^[a-fA-F0-9]{32}$",
    "RIPEMD-160": r"^[a-fA-F0-9]{40}$",
    "RIPEMD-256": r"^[a-fA-F0-9]{64}$",
    "RIPEMD-320": r"^[a-fA-F0-9]{80}$",
    
    # --- Whirlpool ---
    "Whirlpool": r"^[a-fA-F0-9]{128}$",
    
    # --- GOST Family ---
    "GOST R 34.11-94": r"^[a-fA-F0-9]{64}$",
    "GOST R 34.11-2012 (Streebog-256)": r"^[a-fA-F0-9]{64}$",
    "GOST R 34.11-2012 (Streebog-512)": r"^[a-fA-F0-9]{128}$",
    
    # --- BLAKE2 Family ---
    "BLAKE2b-160": r"^[a-fA-F0-9]{40}$",
    "BLAKE2b-256": r"^[a-fA-F0-9]{64}$",
    "BLAKE2b-384": r"^[a-fA-F0-9]{96}$",
    "BLAKE2b-512": r"^[a-fA-F0-9]{128}$",
    "BLAKE2s-224": r"^[a-fA-F0-9]{56}$",
    "BLAKE2s-256": r"^[a-fA-F0-9]{64}$",
    
    # --- SM3 (Chinese Standard) ---
    "SM3": r"^[a-fA-F0-9]{64}$",
    
    # --- Windows / NT Hashes ---
    "NTLM": r"^[a-fA-F0-9]{32}$",
    "LM Hash": r"^[a-fA-F0-9]{32}$",
    "LM (Half)": r"^[a-fA-F0-9]{16}$",
    "NT Hash": r"^[a-fA-F0-9]{32}$",
    
    # --- Unix / Linux Password Hashes ---
    "DES (Unix)": r"^.{2}[a-zA-Z0-9./]{11}$",
    "DES (Crypt)": r"^.{13}$",
    "MD5 Crypt ($1$)": r"^\$1\$[a-zA-Z0-9./]{8,9}\$[a-zA-Z0-9./]{22}$",
    "SHA-256 Crypt ($5$)": r"^\$5\$(rounds=\d+\$)?[a-zA-Z0-9./]{8,16}\$[a-zA-Z0-9./]{43}$",
    "SHA-512 Crypt ($6$)": r"^\$6\$(rounds=\d+\$)?[a-zA-Z0-9./]{8,16}\$[a-zA-Z0-9./]{86}$",
    "Yescrypt": r"^\$y\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]+$",
    "BSDi Crypt (Extended DES)": r"^_[a-zA-Z0-9./]{19}$",
    
    # --- Web Application Hashes ---
    "WordPress (MD5)": r"^\$P\$[A-Za-z0-9./]{31,}$",
    "phpBB3": r"^\$H\$[A-Za-z0-9./]{31,}$",
    "Joomla (MD5 + Salt)": r"^[a-fA-F0-9]{32}:[a-zA-Z0-9]{3,32}$",
    "Drupal (SHA-512 + Salt)": r"^\$S\$[a-zA-Z0-9./]{52}$",
    "Django (MD5)": r"^md5\$[a-zA-Z0-9]+\$[a-fA-F0-9]{32}$",
    "Django (SHA-256)": r"^sha256\$[a-zA-Z0-9]+\$[a-fA-F0-9]{64}$",
    "Django (PBKDF2 SHA256)": r"^pbkdf2_sha256\$[0-9]+\$[a-zA-Z0-9]+\$[a-fA-F0-9]{64}$",
    "PHPass (Portable)": r"^\$P\$[A-Za-z0-9./]{31,}$",
    "Magento": r"^[a-fA-F0-9]{32}:[a-zA-Z0-9]{2}$",
    
    # --- bcrypt / scrypt / Argon2 ---
    "Bcrypt ($2a$)": r"^\$2a\$.{56}$",
    "Bcrypt ($2b$)": r"^\$2b\$.{56}$",
    "Bcrypt ($2x$)": r"^\$2x\$.{56}$",
    "Bcrypt ($2y$)": r"^\$2y\$.{56}$",
    "Scrypt": r"^\$scrypt\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]+$",
    "Argon2i": r"^\$argon2i\$v=\d+\$m=\d+,t=\d+,p=\d+\$[a-zA-Z0-9+/]+$",
    "Argon2id": r"^\$argon2id\$v=\d+\$m=\d+,t=\d+,p=\d+\$[a-zA-Z0-9+/]+$",
    "Argon2d": r"^\$argon2d\$v=\d+\$m=\d+,t=\d+,p=\d+\$[a-zA-Z0-9+/]+$",
    
    # --- Database Hashes ---
    "MySQL (Pre-4.1)": r"^[a-fA-F0-9]{16}$",
    "MySQL (Post-4.1)": r"^\*[a-fA-F0-9]{40}$",
    "MySQL 5.7+": r"^\$A\$005\$[a-fA-F0-9]{62}$",
    "PostgreSQL": r"^md5[a-fA-F0-9]{32}$",
    "PostgreSQL (Challenge)": r"^[a-fA-F0-9]{32}$",
    "MSSQL 2000": r"^0x0100[a-fA-F0-9]{54}$",
    "MSSQL 2005+": r"^0x0100[a-fA-F0-9]{40}$",
    "Oracle 10g": r"^S:[a-fA-F0-9]{60}$",
    "Oracle 11g/12c": r"^S:[a-fA-F0-9]{60}[a-fA-F0-9]{20}$",
    "Oracle (OLD)": r"^[a-fA-F0-9]{16}$",
    
    # --- Cisco / Network Device Hashes ---
    "Cisco Type 4 (SHA-256)": r"^\$4\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]+$",
    "Cisco Type 5 (MD5)": r"^\$1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{22}$",
    "Cisco Type 7": r"^[0-9]{2}[a-fA-F0-9]{2,}$",
    "Cisco PIX / ASA (MD5)": r"^[a-zA-Z0-9+/]{22}==$",
    "Cisco Type 8 (SHA-256)": r"^\$8\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]+$",
    "Cisco Type 9 (Scrypt)": r"^\$9\$[a-zA-Z0-9./]+$",
    "Juniper / Netscreen": r"^\$9\$[a-zA-Z0-9./]{30,}$",
    "Juniper IVE": r"^[a-fA-F0-9]{48}$",
    
    # --- SMB / NetNTLM ---
    "NetNTLMv1": r"^[a-fA-F0-9]{48}:[a-fA-F0-9]{48}$",
    "NetNTLMv1+": r"^[a-fA-F0-9]{48}:[a-fA-F0-9]{48}:[a-fA-F0-9]{48}$",
    "NetNTLMv2": r"^[a-zA-Z0-9.\-_]+:::[a-fA-F0-9]{32}:[a-fA-F0-9]{32}:[a-fA-F0-9]+$",
    "NetNTLMv2 (No Domain)": r"^:::[a-fA-F0-9]{32}:[a-fA-F0-9]{32}:[a-fA-F0-9]+$",
    
    # --- Kerberos ---
    "Kerberos 5 AS-REP (eTYPE 23)": r"^\$krb5asrep\$23\$[a-zA-Z0-9./]+@[a-zA-Z0-9.]+:[a-fA-F0-9]+:[a-fA-F0-9]+$",
    "Kerberos 5 TGS-REP (eTYPE 23)": r"^\$krb5tgs\$23\$[a-zA-Z0-9./]+@[a-zA-Z0-9.]+:[a-fA-F0-9]+:[a-fA-F0-9]+$",
    "Kerberos 5 AS-REP (eTYPE 17)": r"^\$krb5asrep\$17\$[a-zA-Z0-9./]+@[a-zA-Z0-9.]+:[a-fA-F0-9]+:[a-fA-F0-9]+$",
    "Kerberos 5 AS-REP (eTYPE 18)": r"^\$krb5asrep\$18\$[a-zA-Z0-9./]+@[a-zA-Z0-9.]+:[a-fA-F0-9]+:[a-fA-F0-9]+$",
    
    # --- Android ---
    "Android (Samsung)": r"^[a-fA-F0-9]{32}:[0-9]{8}$",
    "Android (Pattern)": r"^[a-fA-F0-9]{32}$",
    
    # --- Other / Checksums ---
    "CRC-32": r"^[a-fA-F0-9]{8}$",
    "CRC-32B": r"^[a-fA-F0-9]{8}$",
    "CRC-16": r"^[a-fA-F0-9]{4}$",
    "Adler-32": r"^[a-fA-F0-9]{8}$",
    "FNV-1 (32-bit)": r"^[a-fA-F0-9]{8}$",
    "FNV-1a (32-bit)": r"^[a-fA-F0-9]{8}$",
    "FNV-1 (64-bit)": r"^[a-fA-F0-9]{16}$",
    "FNV-1a (64-bit)": r"^[a-fA-F0-9]{16}$",
    "MurmurHash (32-bit)": r"^[a-fA-F0-9]{8}$",
    "MurmurHash (128-bit)": r"^[a-fA-F0-9]{32}$",
    "XXHash (32-bit)": r"^[a-fA-F0-9]{8}$",
    "XXHash (64-bit)": r"^[a-fA-F0-9]{16}$",
    "SipHash": r"^[a-fA-F0-9]{16}$",
    "Sum/BSD (16-bit)": r"^[a-fA-F0-9]{4}$",
    "Sum/SysV (16-bit)": r"^[a-fA-F0-9]{4}$",
    
    # --- Other Formats ---
    "CRC-32 (Non-Hex)": r"^[a-zA-Z0-9+/]{6}$",
}


# =============================================================================
# COMPLETE HASHCAT MODE MAPPING
# =============================================================================
HASHCAT_MODES = {
    "MD5": "0", "MD4": "900", "MD2": "9900",
    "SHA-0": "10900", "SHA-1": "100", "SHA-224": "1300",
    "SHA-256": "1400", "SHA-384": "1800", "SHA-512": "1700",
    "SHA-512/224": "21800", "SHA-512/256": "21800",
    "SHA3-224": "17400", "SHA3-256": "17400", "SHA3-384": "17400", "SHA3-512": "17400",
    "SHAKE128 (32B)": "51200", "SHAKE256 (64B)": "51300",
    "RIPEMD-128": "12000", "RIPEMD-160": "6000", "RIPEMD-256": "12000", "RIPEMD-320": "33600",
    "Whirlpool": "6100", "GOST R 34.11-94": "6900",
    "GOST R 34.11-2012 (Streebog-256)": "11700", "GOST R 34.11-2012 (Streebog-512)": "11800",
    "BLAKE2b-160": "60000", "BLAKE2b-256": "60000", "BLAKE2b-384": "60000", "BLAKE2b-512": "60000",
    "BLAKE2s-224": "61400", "BLAKE2s-256": "61400", "SM3": "35100",
    "NTLM": "1000", "LM Hash": "3000", "NT Hash": "1000",
    "DES (Unix)": "1500", "DES (Crypt)": "1500",
    "MD5 Crypt ($1$)": "500", "SHA-256 Crypt ($5$)": "7400", "SHA-512 Crypt ($6$)": "1800",
    "Yescrypt": "25600", "BSDi Crypt (Extended DES)": "12400",
    "WordPress (MD5)": "400", "phpBB3": "400", "Joomla (MD5 + Salt)": "400",
    "Drupal (SHA-512 + Salt)": "7900", "Django (MD5)": "3711", "Django (SHA-256)": "3711",
    "Django (PBKDF2 SHA256)": "10000", "PHPass (Portable)": "400", "Magento": "400",
    "Bcrypt ($2a$)": "3200", "Bcrypt ($2b$)": "3200", "Bcrypt ($2x$)": "3200", "Bcrypt ($2y$)": "3200",
    "Scrypt": "8900", "Argon2i": "29600", "Argon2id": "29700", "Argon2d": "29600",
    "MySQL (Pre-4.1)": "200", "MySQL (Post-4.1)": "300", "MySQL 5.7+": "7401",
    "PostgreSQL": "112", "PostgreSQL (Challenge)": "111",
    "MSSQL 2000": "131", "MSSQL 2005+": "132",
    "Oracle 10g": "3100", "Oracle 11g/12c": "112", "Oracle (OLD)": "3100",
    "Cisco Type 4 (SHA-256)": "9200", "Cisco Type 5 (MD5)": "5700",
    "Cisco PIX / ASA (MD5)": "2400", "Cisco Type 8 (SHA-256)": "9200", "Cisco Type 9 (Scrypt)": "9300",
    "Juniper / Netscreen": "7000", "Juniper IVE": "501",
    "NetNTLMv1": "5500", "NetNTLMv1+": "5500", "NetNTLMv2": "5600", "NetNTLMv2 (No Domain)": "5600",
    "Kerberos 5 AS-REP (eTYPE 23)": "18200", "Kerberos 5 TGS-REP (eTYPE 23)": "13100",
    "Kerberos 5 AS-REP (eTYPE 17)": "19700", "Kerberos 5 AS-REP (eTYPE 18)": "19800",
    "Android (Samsung)": "5800", "Android (Pattern)": "5800",
}


# =============================================================================
# ENCODING / CIPHER / FORMAT DETECTION — 20+ Types
# =============================================================================
def detect_encoding_cipher(data):
    """Detect 20+ different encoding types, cipher formats, and special data formats."""
    results = []
    
    # === Base Encodings ===
    if re.match(r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$", data) and len(data) >= 4:
        results.append(("Base64 (Standard)", "Encoding"))
    if re.match(r"^(?:[A-Za-z0-9\-_]{4})*(?:[A-Za-z0-9\-_]{2}==|[A-Za-z0-9\-_]{3}=)?$", data) and len(data) >= 4:
        results.append(("Base64 URL-Safe", "Encoding"))
    if re.match(r"^[A-Za-z0-9+/]{4,}$", data) and len(data) % 4 != 0:
        results.append(("Base64 (No Padding)", "Encoding"))
    if re.match(r"^(?:[A-Z2-7]{8})*(?:[A-Z2-7]{2}={6}|[A-Z2-7]{4}={4}|[A-Z2-7]{5}={3}|[A-Z2-7]{7}=)?$", data) and len(data) >= 4:
        results.append(("Base32", "Encoding"))
    if re.match(r"^[0-9a-f]+$", data) and len(data) >= 4:
        results.append(("Base16 (Hex Lowercase)", "Encoding"))
    if re.match(r"^[0-9A-F]+$", data) and len(data) >= 4:
        results.append(("Base16 (Hex Uppercase)", "Encoding"))
    if re.match(r"^[1-9A-HJ-NP-Za-km-z]+$", data) and len(data) >= 4:
        results.append(("Base58 (Bitcoin/Wallet)", "Encoding"))
    if re.match(r"^[1-9A-HJ-NP-Za-km-z]*$", data) and len(data) >= 4:
        if not any("Base58" in r[0] for r in results):
            results.append(("Base58 (Ripple/Flickr variant)", "Encoding"))
    if re.match(r"^[0-9A-Za-z]+$", data) and len(data) >= 4:
        results.append(("Base62", "Encoding"))
    if re.match(r"^[0-9A-Z]+$", data) and len(data) >= 4:
        results.append(("Base36", "Encoding"))
    if data.startswith("<~") and data.endswith("~>") and len(data) >= 6:
        results.append(("Ascii85/Base85 (Adobe)", "Encoding"))
    if re.match(r"^[0-9a-zA-Z.\-:+=^!/*?&<>()\[\]{}@%$#]+$", data) and len(data) >= 4:
        results.append(("Base85 (Z85 / RFC 1924)", "Encoding"))
    
    # === Numeric Encodings ===
    if re.match(r"^[01\s]+$", data) and len(data.replace(" ", "")) >= 8:
        results.append(("Binary", "Encoding"))
    if re.match(r"^[0-7\s]+$", data) and len(data.replace(" ", "")) >= 3:
        results.append(("Octal", "Encoding"))
    if re.match(r"^[0-9\s]+$", data) and len(data.replace(" ", "")) >= 4:
        results.append(("Decimal", "Encoding"))
    
    # === Text Encodings ===
    if re.search(r'%[0-9A-Fa-f]{2}', data):
        results.append(("URL Encoded", "Encoding"))
    if re.search(r'%25[0-9A-Fa-f]{2}', data):
        results.append(("Double URL Encoded", "Encoding"))
    if re.search(r'\\u[0-9A-Fa-f]{4}', data):
        results.append(("Unicode Escape Sequence", "Encoding"))
    if re.search(r'&#?[a-zA-Z0-9]+;', data):
        results.append(("HTML Entities", "Encoding"))
    
    # === Cryptographic Key / Certificate Formats ===
    if "-----BEGIN RSA PRIVATE KEY-----" in data:
        results.append(("RSA Private Key (PEM)", "Cryptographic Key"))
    if "-----BEGIN EC PRIVATE KEY-----" in data:
        results.append(("EC Private Key (PEM)", "Cryptographic Key"))
    if "-----BEGIN PGP PRIVATE KEY BLOCK-----" in data:
        results.append(("PGP Private Key", "Cryptographic Key"))
    if "-----BEGIN CERTIFICATE-----" in data:
        results.append(("X.509 Certificate (PEM)", "Cryptographic Key"))
    if "-----BEGIN PGP MESSAGE-----" in data:
        results.append(("PGP Encrypted Message", "Encryption"))
    if "-----BEGIN OPENSSH PRIVATE KEY-----" in data:
        results.append(("OpenSSH Private Key", "Cryptographic Key"))
    if data.startswith("ssh-rsa") or data.startswith("ssh-ed25519") or data.startswith("ecdsa-sha2") or data.startswith("ssh-dss"):
        results.append(("SSH Public Key", "Cryptographic Key"))
    
    # === Token / Data Formats ===
    if re.match(r'^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$', data) and len(data.split('.')) == 3:
        results.append(("JWT Token", "Token"))
    if re.match(r'^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$', data) and len(data.split('.')) == 5:
        results.append(("JWE Token (Encrypted JWT)", "Token"))
    if re.match(r'^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$', data):
        results.append(("UUID / GUID", "Identifier"))
    
    # === Blockchain / Address Formats ===
    if re.match(r'^0x[a-fA-F0-9]{40}$', data):
        results.append(("Ethereum Address", "Blockchain"))
    if re.match(r'^1[a-km-zA-HJ-NP-Z0-9]{25,34}$', data):
        results.append(("Bitcoin Address (P2PKH)", "Blockchain"))
    if re.match(r'^3[a-km-zA-HJ-NP-Z0-9]{25,34}$', data):
        results.append(("Bitcoin Address (P2SH)", "Blockchain"))
    if re.match(r'^bc1[a-km-zA-HJ-NP-Z0-9]{39,59}$', data):
        results.append(("Bitcoin Bech32 Address", "Blockchain"))
    
    # === Cipher Formats ===
    morse_chars = set(data.replace(" ", "").replace("/", ""))
    if morse_chars.issubset({'.', '-', '/', ' '}) and len(data) > 2:
        results.append(("Morse Code", "Cipher"))
    if data.isalpha() and len(data) >= 4:
        try:
            rot13 = codecs.encode(data, 'rot_13')
            common_words = ['the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'can', 'had', 'her', 'was', 'one', 'our', 'out', 'has', 'have', 'been', 'this', 'that', 'with']
            if any(word in rot13.lower() for word in common_words):
                results.append(("ROT13 / Caesar Cipher", "Cipher"))
        except:
            pass
    
    # === Data Serialization ===
    if data.startswith('{') and data.endswith('}'):
        results.append(("JSON Object", "Data Format"))
    if data.startswith('[') and data.endswith(']'):
        results.append(("JSON Array", "Data Format"))
    if data.startswith('<?xml') or (data.startswith('<') and '>' in data and data.endswith('>')):
        results.append(("XML Document", "Data Format"))
    
    return results


# =============================================================================
# HASH GENERATOR MODULE
# =============================================================================
class HashGenerator:
    @staticmethod
    def generate_all(plaintext):
        results = {}
        results["MD5"] = hashlib.md5(plaintext.encode()).hexdigest()
        results["SHA-1"] = hashlib.sha1(plaintext.encode()).hexdigest()
        results["SHA-224"] = hashlib.sha224(plaintext.encode()).hexdigest()
        results["SHA-256"] = hashlib.sha256(plaintext.encode()).hexdigest()
        results["SHA-384"] = hashlib.sha384(plaintext.encode()).hexdigest()
        results["SHA-512"] = hashlib.sha512(plaintext.encode()).hexdigest()
        try:
            results["SHA3-224"] = hashlib.sha3_224(plaintext.encode()).hexdigest()
            results["SHA3-256"] = hashlib.sha3_256(plaintext.encode()).hexdigest()
            results["SHA3-384"] = hashlib.sha3_384(plaintext.encode()).hexdigest()
            results["SHA3-512"] = hashlib.sha3_512(plaintext.encode()).hexdigest()
        except: pass
        try:
            results["BLAKE2b-256"] = hashlib.blake2b(plaintext.encode(), digest_size=32).hexdigest()
            results["BLAKE2b-512"] = hashlib.blake2b(plaintext.encode(), digest_size=64).hexdigest()
            results["BLAKE2s-256"] = hashlib.blake2s(plaintext.encode(), digest_size=32).hexdigest()
        except: pass
        try:
            results["RIPEMD-160"] = hashlib.new('ripemd160', plaintext.encode()).hexdigest()
        except: pass
        try:
            results["NTLM"] = hashlib.new('md4', plaintext.encode('utf-16le')).hexdigest()
        except: pass
        results["Base64"] = base64.b64encode(plaintext.encode()).decode()
        results["Base32"] = base64.b32encode(plaintext.encode()).decode()
        results["Base16 (Hex)"] = plaintext.encode().hex()
        results["ROT13"] = codecs.encode(plaintext, 'rot_13')
        results["Binary"] = ' '.join(format(ord(c), '08b') for c in plaintext)
        results["Octal"] = ' '.join(format(ord(c), '03o') for c in plaintext)
        results["Decimal"] = ' '.join(str(ord(c)) for c in plaintext)
        return results

    @staticmethod
    def menu():
        print(f"\n{Colors.BLUE}" + "="*55 + f"{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}[*] HASH GENERATOR MODULE{Colors.RESET}")
        print(f"{Colors.BLUE}" + "="*55 + f"{Colors.RESET}")
        print(f"{Colors.YELLOW}[!] Generate ALL possible hashes and encodings for any word.{Colors.RESET}\n")
        
        while True:
            plaintext = input(f"{Colors.GREEN}Enter word to hash (or 'q' to exit): {Colors.RESET}").strip()
            if plaintext.lower() == 'q': return
            if not plaintext: continue
            
            print(f"\n{Colors.BLUE}" + "="*55 + f"{Colors.RESET}")
            print(f"{Colors.BOLD}Results for:{Colors.RESET} {Colors.GREEN}{Colors.BOLD}{plaintext}{Colors.RESET}")
            print(f"{Colors.BLUE}" + "="*55 + f"{Colors.RESET}")
            
            results = HashGenerator.generate_all(plaintext)
            
            categories = {
                "MD & SHA": ["MD5", "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"],
                "SHA3": ["SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"],
                "BLAKE2": ["BLAKE2b-256", "BLAKE2b-512", "BLAKE2s-256"],
                "Other Hashes": ["RIPEMD-160", "NTLM"],
                "Encodings": ["Base64", "Base32", "Base16 (Hex)"],
                "Transformations": ["ROT13", "Binary", "Octal", "Decimal"]
            }
            
            for cat, keys in categories.items():
                valid = [k for k in keys if k in results]
                if not valid: continue
                print(f"\n{Colors.CYAN}[ {cat} ]{Colors.RESET}")
                print(f"{Colors.BLUE}" + "-"*55 + f"{Colors.RESET}")
                for key in valid:
                    val = str(results[key])
                    disp = val[:57] + "..." if len(val) > 60 else val
                    print(f"  {Colors.YELLOW}{key:<20}{Colors.RESET}: {Colors.GREEN}{disp}{Colors.RESET}")
            
            print(f"\n{Colors.MAGENTA}[*] Total: {len(results)} hashes/encodings generated{Colors.RESET}")
            
            if input(f"\n{Colors.YELLOW}[?] Save to file? (y/n): {Colors.RESET}").lower() == 'y':
                fn = f"hashes_{plaintext}_{int(time.time())}.txt"
                with open(fn, 'w') as f:
                    f.write(f"HashHound Pro Report\nPlaintext: {plaintext}\n{'='*60}\n\n")
                    for k, v in results.items():
                        f.write(f"{k}: {v}\n")
                print(f"{Colors.GREEN}[+] Saved to {fn}{Colors.RESET}")
            print()


# =============================================================================
# HASHCAT CRACKING ENGINE
# =============================================================================
class HashcatCracker:
    def __init__(self, hash_data, hash_type, mode_num):
        self.data = hash_data.strip()
        self.hash_type = hash_type
        self.mode_num = mode_num

    def simulate_loading(self, task_name):
        sys.stdout.write(f"{Colors.YELLOW}[*] {task_name}... {Colors.RESET}")
        sys.stdout.flush()
        for _ in range(3):
            time.sleep(0.2)
            sys.stdout.write(f"{Colors.YELLOW}.{Colors.RESET}")
            sys.stdout.flush()
        print(f"{Colors.GREEN} Done!{Colors.RESET}")

    def select_rule_file(self):
        print(f"\n{Colors.BLUE}" + "-"*55 + f"{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}[*] RULE SELECTION{Colors.RESET}")
        print(f"{Colors.BLUE}" + "-"*55 + f"{Colors.RESET}")
        rule_dirs = ["/usr/share/hashcat/rules/", "/usr/share/hashcat/rules", "/usr/share/wordlists/"]
        available_rules = []
        for d in rule_dirs:
            if os.path.isdir(d):
                for f in os.listdir(d):
                    if f.endswith(".rule"):
                        available_rules.append(os.path.join(d, f))
        seen = {}
        for r in available_rules:
            base = os.path.basename(r)
            if base not in seen:
                seen[base] = r
        sorted_rules = sorted(seen.items())
        
        if not sorted_rules:
            print(f"{Colors.YELLOW}[!] No .rule files found automatically.{Colors.RESET}")
            manual = input(f"{Colors.CYAN}[?] Enter rule file path (or Enter to skip): {Colors.RESET}").strip()
            return manual if manual and os.path.isfile(manual) else None
        
        print(f"{Colors.WHITE}[*] Available Rule Files:{Colors.RESET}")
        for i, (base, full) in enumerate(sorted_rules, 1):
            print(f"    {Colors.YELLOW}[{i}]{Colors.RESET} {base}")
        print(f"    {Colors.YELLOW}[{len(sorted_rules)+1}]{Colors.RESET} Custom path")
        print(f"    {Colors.RED}[{len(sorted_rules)+2}]{Colors.RESET} Skip / No Rule")
        choice = input(f"\n{Colors.YELLOW}[?] Select (1-{len(sorted_rules)+2}): {Colors.RESET}").strip()
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(sorted_rules):
                return sorted_rules[idx-1][1]
            elif idx == len(sorted_rules) + 1:
                p = input(f"{Colors.CYAN}Path: {Colors.RESET}").strip()
                return p if os.path.isfile(p) else None
        return None

    def wordlist_attack(self, hash_file):
        print(f"\n{Colors.BLUE}" + "-"*55 + f"{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}[*] WORDLIST ATTACK MODE{Colors.RESET}")
        print(f"{Colors.BLUE}" + "-"*55 + f"{Colors.RESET}")
        print(f"  {Colors.YELLOW}[1]{Colors.RESET} rockyou.txt")
        print(f"  {Colors.YELLOW}[2]{Colors.RESET} Custom Wordlist")
        print(f"  {Colors.RED}[3]{Colors.RESET} Back")
        wl = input(f"\n{Colors.YELLOW}[?] Choose: {Colors.RESET}").strip()
        
        if wl == '3': return False
        
        wordlist = "/usr/share/wordlists/rockyou.txt" if wl == '1' else input(f"{Colors.CYAN}Path: {Colors.RESET}").strip()
        if not os.path.isfile(wordlist):
            print(f"{Colors.RED}[-] Wordlist not found.{Colors.RESET}")
            return False
        
        print(f"\n{Colors.CYAN}[>] hashcat -m {self.mode_num} -a 0 {hash_file} {os.path.basename(wordlist)}{Colors.RESET}\n")
        if input(f"{Colors.YELLOW}[?] Run? (y/n): {Colors.RESET}").lower() == 'y':
            self.simulate_loading("Hashcat Wordlist Attack")
            try:
                cmd = ["hashcat", "-m", self.mode_num, "-a", "0", hash_file, wordlist]
                if os.name == 'nt': subprocess.run(cmd, shell=True)
                else: subprocess.run(cmd)
                show = subprocess.run(["hashcat", "-m", self.mode_num, "--show", hash_file], capture_output=True, text=True, shell=(os.name == 'nt'))
                out = show.stdout.strip()
                if out:
                    pw = out.split('\n')[0].split(':')[-1]
                    print(f"\n{Colors.GREEN}[+] PASSWORD: {Colors.RED}{Colors.BOLD}{pw}{Colors.RESET}\n")
                else:
                    print(f"\n{Colors.YELLOW}[-] Not found.{Colors.RESET}\n")
            except FileNotFoundError:
                print(f"\n{Colors.RED}hashcat not installed.{Colors.RESET}")
        return True

    def rule_attack(self, hash_file):
        rule = self.select_rule_file()
        if not rule: return False
        
        print(f"\n{Colors.BLUE}" + "-"*55 + f"{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}[*] WORDLIST FOR RULE ATTACK{Colors.RESET}")
        print(f"{Colors.BLUE}" + "-"*55 + f"{Colors.RESET}")
        print(f"  {Colors.YELLOW}[1]{Colors.RESET} rockyou.txt")
        print(f"  {Colors.YELLOW}[2]{Colors.RESET} Custom")
        print(f"  {Colors.RED}[3]{Colors.RESET} Back")
        wl = input(f"\n{Colors.YELLOW}[?] Choose: {Colors.RESET}").strip()
        
        if wl == '3': return False
        
        wordlist = "/usr/share/wordlists/rockyou.txt" if wl == '1' else input(f"{Colors.CYAN}Path: {Colors.RESET}").strip()
        if not os.path.isfile(wordlist):
            print(f"{Colors.RED}[-] Wordlist not found.{Colors.RESET}")
            return False
        
        print(f"\n{Colors.CYAN}[>] hashcat -m {self.mode_num} -a 0 {hash_file} {os.path.basename(wordlist)} -r {os.path.basename(rule)}{Colors.RESET}\n")
        if input(f"{Colors.YELLOW}[?] Run? (y/n): {Colors.RESET}").lower() == 'y':
            self.simulate_loading("Hashcat Rule Attack")
            try:
                cmd = ["hashcat", "-m", self.mode_num, "-a", "0", hash_file, wordlist, "-r", rule]
                if os.name == 'nt': subprocess.run(cmd, shell=True)
                else: subprocess.run(cmd)
                show = subprocess.run(["hashcat", "-m", self.mode_num, "--show", hash_file], capture_output=True, text=True, shell=(os.name == 'nt'))
                out = show.stdout.strip()
                if out:
                    pw = out.split('\n')[0].split(':')[-1]
                    print(f"\n{Colors.GREEN}[+] PASSWORD: {Colors.RED}{Colors.BOLD}{pw}{Colors.RESET}\n")
                else:
                    print(f"\n{Colors.YELLOW}[-] Not found.{Colors.RESET}\n")
            except FileNotFoundError:
                print(f"\n{Colors.RED}hashcat not installed.{Colors.RESET}")
        return True

    def mask_attack(self, hash_file):
        print(f"\n{Colors.BLUE}" + "-"*55 + f"{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}[*] MASK ATTACK MODE{Colors.RESET}")
        print(f"{Colors.BLUE}" + "-"*55 + f"{Colors.RESET}")
        print(f"  {Colors.YELLOW}?l{Colors.RESET}=lower {Colors.YELLOW}?u{Colors.RESET}=upper {Colors.YELLOW}?d{Colors.RESET}=digit {Colors.YELLOW}?s{Colors.RESET}=symbol {Colors.YELLOW}?a{Colors.RESET}=all")
        print(f"  Example: {Colors.CYAN}?u?l?l?l?l?d?d?d{Colors.RESET} for 'Admin123'\n")
        mask = input(f"{Colors.GREEN}Mask > {Colors.RESET}").strip()
        if not mask: return False
        
        print(f"\n{Colors.CYAN}[>] hashcat -m {self.mode_num} -a 3 {hash_file} {mask}{Colors.RESET}\n")
        if input(f"{Colors.YELLOW}[?] Run? (y/n): {Colors.RESET}").lower() == 'y':
            self.simulate_loading("Hashcat Mask Attack")
            try:
                cmd = ["hashcat", "-m", self.mode_num, "-a", "3", hash_file, mask]
                if os.name == 'nt': subprocess.run(cmd, shell=True)
                else: subprocess.run(cmd)
                show = subprocess.run(["hashcat", "-m", self.mode_num, "--show", hash_file], capture_output=True, text=True, shell=(os.name == 'nt'))
                out = show.stdout.strip()
                if out:
                    pw = out.split('\n')[0].split(':')[-1]
                    print(f"\n{Colors.GREEN}[+] PASSWORD: {Colors.RED}{Colors.BOLD}{pw}{Colors.RESET}\n")
                else:
                    print(f"\n{Colors.YELLOW}[-] Not found.{Colors.RESET}\n")
            except FileNotFoundError:
                print(f"\n{Colors.RED}hashcat not installed.{Colors.RESET}")
        return True

    def run(self):
        hash_file = "temp_hash.txt"
        with open(hash_file, "w") as f:
            f.write(self.data)
        
        while True:
            print(f"\n{Colors.BLUE}" + "="*55 + f"{Colors.RESET}")
            print(f"{Colors.BOLD}{Colors.CYAN}[*] HASHCAT CRACKING - {self.hash_type} (-m {self.mode_num}){Colors.RESET}")
            print(f"{Colors.BLUE}" + "="*55 + f"{Colors.RESET}")
            print(f"  {Colors.YELLOW}[1]{Colors.RESET} Wordlist Attack")
            print(f"  {Colors.YELLOW}[2]{Colors.RESET} Rule-Based Attack")
            print(f"  {Colors.YELLOW}[3]{Colors.RESET} Mask Attack (Brute-force)")
            print(f"  {Colors.RED}[4]{Colors.RESET} Exit Cracking")
            
            c = input(f"\n{Colors.YELLOW}[?] Choose (1-4): {Colors.RESET}").strip()
            
            if c == '1':
                if self.wordlist_attack(hash_file): break
            elif c == '2':
                if self.rule_attack(hash_file): break
            elif c == '3':
                if self.mask_attack(hash_file): break
            elif c == '4':
                break
        
        if os.path.exists(hash_file): os.remove(hash_file)


# =============================================================================
# HASH FINDER MODULE — Finds hash + Auto-launches Hashcat
# =============================================================================
class HashFinder:
    @staticmethod
    def analyze_single(target):
        """Single hash analysis with table output."""
        print(f"\n{Colors.CYAN}[>] Target Input : {Colors.WHITE}{target[:50]}{'...' if len(target) > 50 else ''}{Colors.RESET}\n")
        
        # Step 1: Identify hash type
        hash_matches = []
        for name, pattern in HASH_PATTERNS.items():
            if re.match(pattern, target):
                mode = HASHCAT_MODES.get(name, None)
                hash_matches.append((name, mode))
        
        # Step 2: Check encodings
        enc_matches = detect_encoding_cipher(target)
        
        # Table output
        print(f"{Colors.BLUE}+------+---------------------------------------------+-------------------------------------+{Colors.RESET}")
        print(f"{Colors.BLUE}|{Colors.RESET} {Colors.BOLD}ID{Colors.RESET}   {Colors.BLUE}|{Colors.RESET} {Colors.BOLD}Category{Colors.RESET}                                        {Colors.BLUE}|{Colors.RESET} {Colors.BOLD}Identified Type{Colors.RESET}                          {Colors.BLUE}|{Colors.RESET}")
        print(f"{Colors.BLUE}+------+---------------------------------------------+-------------------------------------+{Colors.RESET}")
        
        row_id = 1
        if hash_matches:
            for name, mode in hash_matches:
                mode_str = f" (hashcat -m {mode})" if mode else " (no hashcat mode)"
                disp_type = f"{name}{mode_str}"
                print(f"{Colors.BLUE}|{Colors.RESET} {Colors.YELLOW}{row_id:02d}{Colors.RESET}   {Colors.BLUE}|{Colors.RESET} {Colors.CYAN}Cryptographic Hash{Colors.RESET}               {Colors.BLUE}|{Colors.RESET} {Colors.GREEN}{disp_type:<35}{Colors.RESET} {Colors.BLUE}|{Colors.RESET}")
                row_id += 1
        else:
            print(f"{Colors.BLUE}|{Colors.RESET} {Colors.YELLOW}{row_id:02d}{Colors.RESET}   {Colors.BLUE}|{Colors.RESET} {Colors.CYAN}Cryptographic Hash{Colors.RESET}               {Colors.BLUE}|{Colors.RESET} {Colors.RED}No hash pattern matched{' '*27}{Colors.RESET} {Colors.BLUE}|{Colors.RESET}")
            row_id += 1
        
        if enc_matches:
            for name, cat in enc_matches:
                disp_line = f"{name} ({cat})"[:38]
                print(f"{Colors.BLUE}|{Colors.RESET} {Colors.YELLOW}{row_id:02d}{Colors.RESET}   {Colors.BLUE}|{Colors.RESET} {Colors.CYAN}Encoding / Format{Colors.RESET}                  {Colors.BLUE}|{Colors.RESET} {Colors.GREEN}{disp_line:<35}{Colors.RESET} {Colors.BLUE}|{Colors.RESET}")
                row_id += 1
        
        # Entropy
        freq = {c: target.count(c) for c in set(target)}
        entropy = -sum((c/len(target))*math.log2(c/len(target)) for c in freq.values()) if len(target) > 0 else 0
        print(f"{Colors.BLUE}|{Colors.RESET} {Colors.YELLOW}{row_id:02d}{Colors.RESET}   {Colors.BLUE}|{Colors.RESET} {Colors.CYAN}Analysis{Colors.RESET}                              {Colors.BLUE}|{Colors.RESET} {Colors.WHITE}Length: {len(target)} | Entropy: {entropy:.3f}{Colors.RESET}          {Colors.BLUE}|{Colors.RESET}")
        
        print(f"{Colors.BLUE}+------+---------------------------------------------+-------------------------------------+{Colors.RESET}\n")
        
        # Step 3: Auto-launch cracking for hash matches
        if hash_matches and hash_matches[0][1]:
            best_type, best_mode = hash_matches[0]
            print(f"{Colors.GREEN}[+] Detected: {best_type} | Hashcat Mode: -m {best_mode}{Colors.RESET}")
            print(f"{Colors.GREEN}[+] Launching Hashcat cracking menu...{Colors.RESET}")
            cracker = HashcatCracker(target, best_type, best_mode)
            cracker.run()
        elif hash_matches and not hash_matches[0][1]:
            print(f"{Colors.YELLOW}[!] Hash identified but no hashcat mode available for cracking.{Colors.RESET}")
        else:
            # Try to decode encodings
            for name, cat in enc_matches:
                if "Base64" in name and "Standard" in name:
                    try:
                        pad = (4 - (len(target) % 4)) % 4
                        decoded = base64.b64decode(target + "=" * pad).decode('utf-8')
                        print(f"{Colors.GREEN}[+] Base64 Decoded: {Colors.WHITE}{decoded}{Colors.RESET}\n")
                    except: pass
                elif "ROT13" in name:
                    decoded = codecs.encode(target, 'rot_13')
                    print(f"{Colors.GREEN}[+] ROT13 Decoded: {Colors.WHITE}{decoded}{Colors.RESET}\n")
            
            # Offer manual hashcat
            if input(f"{Colors.YELLOW}[?] Try Hashcat with manual mode? (y/n): {Colors.RESET}").lower() == 'y':
                mode = input(f"{Colors.CYAN}Enter hashcat mode (-m): {Colors.RESET}").strip()
                if mode and mode.isdigit():
                    cracker = HashcatCracker(target, "Manual Mode", mode)
                    cracker.run()

    @staticmethod
    def process_file(filepath):
        """Process a file with table output."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                lines = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"{Colors.RED}[-] Error reading file: {e}{Colors.RESET}")
            return
        
        if not lines:
            print(f"{Colors.RED}[-] File is empty.{Colors.RESET}")
            return
        
        print(f"\n{Colors.CYAN}[*] Analyzed {len(lines)} entries from '{filepath}':{Colors.RESET}\n")
        
        border = f"{Colors.BLUE}+------+------------------------+---------------------------------------+{Colors.RESET}"
        header = f"{Colors.BLUE}|{Colors.RESET} {Colors.BOLD}ID{Colors.RESET}   {Colors.BLUE}|{Colors.RESET} {Colors.BOLD}Hash/Cipher (Preview){Colors.RESET}  {Colors.BLUE}|{Colors.RESET} {Colors.BOLD}Identified Type{Colors.RESET}                       {Colors.BLUE}|{Colors.RESET}"
        
        print(border)
        print(header)
        print(border)
        
        results = []
        for idx, line in enumerate(lines, 1):
            # Identify hash
            hash_matches = []
            for name, pattern in HASH_PATTERNS.items():
                if re.match(pattern, line):
                    mode = HASHCAT_MODES.get(name, None)
                    hash_matches.append((name, mode))
            
            if hash_matches:
                spec_type = hash_matches[0][0]
                cat = "Cryptographic Hash"
            else:
                enc = detect_encoding_cipher(line)
                if enc:
                    spec_type = enc[0][0]
                    cat = enc[0][1]
                else:
                    spec_type = "Unrecognized"
                    cat = "Unknown"
            
            results.append((line, cat, spec_type))
            
            disp_line = line[:20] + ".." if len(line) > 20 else line
            print(f"{Colors.BLUE}|{Colors.RESET} {Colors.YELLOW}{idx:02d}{Colors.RESET}   {Colors.BLUE}|{Colors.RESET} {Colors.WHITE}{disp_line:<22}{Colors.RESET} {Colors.BLUE}|{Colors.RESET} {Colors.GREEN}{spec_type:<37}{Colors.RESET} {Colors.BLUE}|{Colors.RESET}")
        
        print(border + "\n")
        
        completed_results = {}
        
        while True:
            choice = input(f"\n{Colors.YELLOW}[?] Enter ID to crack/decode (or 'q' to return): {Colors.RESET}").strip()
            
            if choice.lower() in ['q', 'quit', 'exit', 'b', 'back']:
                print(f"{Colors.CYAN}[*] Returning to main menu...{Colors.RESET}")
                return
            
            if choice.isdigit():
                idx = int(choice)
                if 1 <= idx <= len(results):
                    selected_line, cat, spec_type = results[idx - 1]
                    
                    if idx in completed_results:
                        print(f"\n{Colors.GREEN}[*] ID #{idx} was already processed!{Colors.RESET}")
                        if cat != "Cryptographic Hash":
                            print(f"{Colors.BOLD}[3] SAVED RESULT :{Colors.RESET} {completed_results[idx]}")
                        else:
                            print(f"{Colors.YELLOW}[*] Hashcat was already executed. (Check potfile){Colors.RESET}")
                        recheck = input(f"\n{Colors.YELLOW}[?] Re-process? (y/n): {Colors.RESET}").strip().lower()
                        if recheck != 'y': continue
                    
                    print(f"\n{Colors.CYAN}[*] Processing Entry #{idx}: {spec_type}{Colors.RESET}")
                    
                    # Get hashcat mode
                    mode = None
                    for name, pattern in HASH_PATTERNS.items():
                        if re.match(pattern, selected_line) and name == spec_type:
                            mode = HASHCAT_MODES.get(name)
                            break
                    
                    if mode:
                        cracker = HashcatCracker(selected_line, spec_type, mode)
                        cracker.run()
                        completed_results[idx] = f"Hashcat executed for {spec_type} (-m {mode})"
                    elif cat != "Cryptographic Hash":
                        # Try to decode
                        if "Base64" in spec_type and "Standard" in spec_type:
                            try:
                                pad = (4 - (len(selected_line) % 4)) % 4
                                decoded = base64.b64decode(selected_line + "=" * pad).decode('utf-8')
                                res = f"{Colors.GREEN}{decoded}{Colors.RESET} (Decoded Base64)"
                                print(f"\n{Colors.BOLD}[3] RESULT :{Colors.RESET} {res}\n")
                                completed_results[idx] = f"Decoded: {decoded}"
                            except: pass
                        elif "ROT13" in spec_type:
                            decoded = codecs.encode(selected_line, 'rot_13')
                            res = f"{Colors.GREEN}{decoded}{Colors.RESET} (Decrypted ROT13)"
                            print(f"\n{Colors.BOLD}[3] RESULT :{Colors.RESET} {res}\n")
                            completed_results[idx] = f"Decoded: {decoded}"
                        else:
                            print(f"{Colors.YELLOW}[!] No auto-decoding available for this type.{Colors.RESET}")
                            # Try manual hashcat
                            if input(f"{Colors.YELLOW}[?] Try Hashcat manually? (y/n): {Colors.RESET}").lower() == 'y':
                                m = input(f"{Colors.CYAN}Enter mode (-m): {Colors.RESET}").strip()
                                if m and m.isdigit():
                                    cracker = HashcatCracker(selected_line, "Manual", m)
                                    cracker.run()
                                    completed_results[idx] = f"Hashcat (-m {m}) executed"
                    else:
                        print(f"{Colors.YELLOW}[!] No hashcat mode for this hash type.{Colors.RESET}")
                    
                    print(f"{Colors.MAGENTA}[*] Task completed for ID #{idx}.{Colors.RESET}")
                else:
                    print(f"{Colors.RED}[-] Invalid ID.{Colors.RESET}")
            else:
                print(f"{Colors.RED}[-] Enter a number or 'q'.{Colors.RESET}")

    @staticmethod
    def menu():
        print(f"\n{Colors.BLUE}" + "="*55 + f"{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}[*] HASH FINDER + AUTO CRACK MODULE{Colors.RESET}")
        print(f"{Colors.BLUE}" + "="*55 + f"{Colors.RESET}")
        print(f"{Colors.YELLOW}[!] Enter a hash/ciphertext or a file path (e.g., hashes.txt){Colors.RESET}\n")
        
        while True:
            target = input(f"{Colors.GREEN}HashHound > {Colors.RESET}").strip()
            if target.lower() in ['q', 'quit', 'exit', 'back']:
                return
            if not target: continue
            
            if os.path.isfile(target):
                HashFinder.process_file(target)
            else:
                HashFinder.analyze_single(target)


# =============================================================================
# MAIN MENU — Only 2 Options
# =============================================================================
def show_main_menu():
    print(f"\n{Colors.BLUE}" + "="*55 + f"{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}MAIN MENU{Colors.RESET}")
    print(f"{Colors.BLUE}" + "="*55 + f"{Colors.RESET}")
    print(f"  {Colors.YELLOW}[1]{Colors.RESET} Hash Generator")
    print(f"  {Colors.YELLOW}[2]{Colors.RESET} Hash Finder + Auto Crack (Wordlist | Rule | Mask)")
    print(f"  {Colors.RED}[3]{Colors.RESET} Exit")
    print(f"{Colors.BLUE}" + "-"*55 + f"{Colors.RESET}")


def main():
    print_startup_banner()
    
    while True:
        show_main_menu()
        choice = input(f"\n{Colors.GREEN}HashHound > {Colors.RESET}").strip()
        
        if choice == '1':
            HashGenerator.menu()
        elif choice == '2':
            HashFinder.menu()
        elif choice in ['3', 'q']:
            print(f"\n{Colors.RED}Goodbye!{Colors.RESET}")
            break


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.RED}[!] Interrupted.{Colors.RESET}")
        sys.exit(0)