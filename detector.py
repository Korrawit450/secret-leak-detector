import sys
import os
import re
from colorama import Fore, Style, init

init(autoreset=True)

# รายการ Regular Expressions สำหรับตรวจจับ API Keys และ Credentials สำคัญ
SECRET_PATTERNS = {
    "AWS Access Key ID": re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
    "AWS Secret Access Key": re.compile(r"(?i)aws_secret_access_key\s*=\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
    "GitHub Personal Access Token": re.compile(r"\b(ghp_[0-9a-zA-Z]{36})\b"),
    "Slack Webhook URL": re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Z]{8}/B[0-9A-Z]{8,12}/[0-9a-zA-Z]{24}"),
    "Generic Private Key": re.compile(r"-----BEGIN (RSA|OPENSSH|EC|DSA)? PRIVATE KEY-----"),
    "JSON Web Token (JWT)": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}\b"),
    "Generic API Key / Secret": re.compile(r"(?i)(api[_-]?key|secret[_-]?token|auth[_-]?token)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,64})['\"]")
}

IGNORE_DIRS = {".git", "node_modules", "__pycache__", "venv", ".venv"}
IGNORE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".tar", ".gz", ".exe"}

def mask_secret(secret: str) -> str:
    """ซ่อนข้อความความลับบางส่วนเพื่อความปลอดภัยในการแสดงผล"""
    if len(secret) <= 8:
        return "****"
    return secret[:4] + "*" * (len(secret) - 8) + secret[-4:]

def scan_file(file_path: str):
    findings = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_idx, line in enumerate(f, start=1):
                clean_line = line.strip()
                if not clean_line:
                    continue
                for secret_name, regex in SECRET_PATTERNS.items():
                    match = regex.search(clean_line)
                    if match:
                        matched_text = match.group(0)
                        findings.append((line_idx, secret_name, matched_text))
    except Exception:
        pass
    return findings

def scan_directory(target_path: str):
    print(f"\n{Fore.CYAN}=== Secret & Credential Leak Scanner ==={Style.RESET_ALL}")
    print(f"Target Path: {os.path.abspath(target_path)}\n")

    total_files = 0
    total_findings = 0

    print(f"{'Line':<6} | {'Finding Type':<28} | {'File / Masked Value'}")
    print("-" * 85)

    for root, dirs, files in os.walk(target_path):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext in IGNORE_EXTS:
                continue

            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, target_path)
            total_files += 1

            findings = scan_file(full_path)
            if findings:
                print(f"{Fore.YELLOW}File: {rel_path}{Style.RESET_ALL}")
                for line_idx, secret_type, matched_str in findings:
                    total_findings += 1
                    masked = mask_secret(matched_str)
                    print(f"  {line_idx:<4} | {Fore.RED}{secret_type:<28}{Style.RESET_ALL} | {masked}")
                print("-" * 85)

    print(f"\nScanned: {total_files} file(s)")
    if total_findings > 0:
        print(f"Status : {Fore.RED}Detected {total_findings} potential secret exposure(s)!{Style.RESET_ALL}\n")
    else:
        print(f"Status : {Fore.GREEN}Clean. No credential exposures identified.{Style.RESET_ALL}\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python detector.py <target-file-or-directory>")
        sys.exit(1)

    target = sys.argv[1]
    if os.path.isfile(target):
        findings = scan_file(target)
        print(f"\nScanning Single File: {target}")
        for line_idx, secret_type, matched_str in findings:
            print(f"  Line {line_idx}: [{secret_type}] -> {mask_secret(matched_str)}")
    elif os.path.isdir(target):
        scan_directory(target)
    else:
        print(f"{Fore.RED}[!] Target path does not exist.{Style.RESET_ALL}")