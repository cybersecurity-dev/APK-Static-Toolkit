import re
import zipfile

from pathlib import Path
from typing import List

def extract_strings_from_apk(apk_path: Path, min_length: int = 5) -> List[str] | None:
    strings = set()
    try:
        with zipfile.ZipFile(apk_path, 'r') as apk:
            # Extract strings from all files in the APK
            for file_info in apk.filelist:
                try:
                    data = apk.read(file_info.filename)
                    try:
                        # Try to decode as UTF-8 and extract printable strings
                        text = data.decode('utf-8', errors='ignore')
                        # Find sequences of printable ASCII characters
                        found = re.findall(r'[\x20-\x7E]{' + str(min_length) + r',}', text)
                        strings.update(found)
                    except:
                        pass
                    
                    # Also extract as raw bytes for binary files
                    found = re.findall(b'[\x20-\x7E]{' + str(min_length).encode() + b',}', data)
                    strings.update(s.decode('ascii', errors='ignore') for s in found)
                    
                except Exception as e:
                    continue # Skip files that can't be read
    except Exception as e:
        #raise Exception(f"Error reading APK file: {e}")
        print(f"Error reading APK file: {e}")
        return None  
    return sorted(list(strings))

#---------------------------------------------------------------------------------------------------------------------

def extract_important_strings_from_apk(apk_path: Path) -> dict:
    patterns = {
        'urls': re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+'),
        'ips': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
        'emails': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        'domains': re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'),
        'api_keys': re.compile(r'(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|secret[_-]?key)[\s:=]+["\']?([a-zA-Z0-9_\-]{20,})["\']?', re.IGNORECASE),
        'file_paths': re.compile(r'(?:/[a-zA-Z0-9_.-]+)+/?|(?:[A-Z]:\\(?:[^\\\s]+\\)*[^\\\s]+)'),
        'base64': re.compile(r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'),
        'crypto_keys': re.compile(r'-----BEGIN [A-Z ]+-----[\s\S]+?-----END [A-Z ]+-----|MII[A-Za-z0-9+/=]{100,}')
    }

    results = {key: set() for key in patterns.keys()}

    try:
        # First, get all strings from the APK
        all_strings = extract_strings_from_apk(apk_path, min_length=3)

        # Search for patterns in each string
        for string in all_strings:
            for category, pattern in patterns.items():
                matches = pattern.findall(string)
                if matches:
                    if category == 'api_keys':
                        # For API keys, extract the captured group
                        results[category].update(match if isinstance(match, str) else match for match in matches)
                    else:
                        results[category].update(matches if isinstance(matches, list) else [matches])

        # Post-processing and filtering
        # Remove invalid IPs
        valid_ips = set()
        for ip in results['ips']:
            parts = ip.split('.')
            if all(0 <= int(part) <= 255 for part in parts):
                # Skip common invalid IPs
                if not ip.startswith(('0.0.', '255.255.255.255')):
                    valid_ips.add(ip)
        results['ips'] = valid_ips

        # Filter base64 strings (only keep longer ones, likely to be real)
        #results['base64'] = {b64 for b64 in results['base64'] if len(b64) > 20}

        # Remove domains that are already in URLs
        url_domains = set()
        for url in results['urls']:
            match = re.search(r'://([^/]+)', url)
            if match:
                url_domains.add(match.group(1))
        results['domains'] = results['domains'] - url_domains

        # Filter out common/system file paths
        system_paths = {'/system', '/data', '/dev', '/proc', '/sys'}
        results['file_paths'] = {path for path in results['file_paths']
                                 if not any(path.startswith(sp) for sp in system_paths)
                                 and len(path) > 5}

    except Exception as e:
        raise Exception(f"Error extracting important strings: {e}")

    # Convert sets to sorted lists
    return {key: sorted(list(value)) for key, value in results.items()}
#---------------------------------------------------------------------------------------------------------------------


#---------------------------------------------------------
# IMPORTANT STRING PATTERNS
#---------------------------------------------------------
 
# File path: starts with / or ./ or ../ or a Windows drive letter
_RE_FILE_PATH = re.compile(
    r'^(?:(?:/|\.{1,2}/)[\w./ \-]+|[a-zA-Z]:\\[\w\\.\- ]+)$'
)
 
# URL: http/https/ftp/file schemes or bare domains
_RE_URL = re.compile(
    r'^(?:https?|ftp|file)://[^\s"\'<>]{4,}'
    r'|^(?:www\.)[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}(?:[/\?\#][^\s]*)?$',
    re.IGNORECASE
)
 
# IPv4 address (plain or with port)
_RE_IP = re.compile(
    r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)'
    r'(?::\d{1,5})?$'
)
 
# IPv6 address (simplified)
_RE_IPV6 = re.compile(
    r'^(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}$'
)

# Covers PEM blocks, raw hex keys (128–512-bit), and SSH public-key blobs.
_RE_CRYPTO_KEYS = re.compile(
    r'-----BEGIN\s+(?:RSA |EC |DSA |OPENSSH |PGP )?(?:PRIVATE|PUBLIC) KEY-----'   # PEM header
    r'|-----BEGIN CERTIFICATE-----'                                               # X.509 cert
    r'|^[0-9a-fA-F]{32,128}$'                                                     # raw hex key (128–512 bit range)
    r'|^(?:ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp\d+)\s+[A-Za-z0-9+/=]{20,}',       # SSH pubkey
    re.MULTILINE,
)

# At least 16 chars of base64 alphabet, length a multiple of 4, with ≥1 '='.
# The second branch catches long unpadded payloads (≥32 chars, > 80 % b64 chars).
_RE_BASE64 = re.compile(
    r'^(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$'   # padded
    r'|^[A-Za-z0-9+/\-_]{32,}$',                                             # unpadded / URL-safe
)

# Well-known vendor prefixes followed by opaque alphanumeric tokens.
_RE_API_KEYS = re.compile(
    # Firebase / Google
    r'AIza[0-9A-Za-z\-_]{35}'
    # AWS access key ID
    r'|(?:AKIA|ASIA|AROA|AIDA)[0-9A-Z]{16}'
    # AWS secret access key (preceded by common label)
    r'|(?:aws_secret|secret_key|secretKey)\s*[=:]\s*[0-9A-Za-z/+]{40}'
    # GitHub personal access token (classic & fine-grained)
    r'|(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,255}'
    # Stripe live / test secret
    r'|sk_(?:live|test)_[0-9a-zA-Z]{24,}'
    # Slack bot / user token
    r'|xox[baprs]-[0-9A-Za-z\-]{10,}'
    # Twilio account SID
    r'|AC[0-9a-f]{32}'
    # SendGrid
    r'|SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{43,}'
    # Generic "Bearer <token>" or "Authorization: <token>"
    r'|(?:Bearer|Authorization)\s+[A-Za-z0-9\-_.~+/]{20,}'
    # Generic high-entropy tokens labelled with common key names
    r'|(?:api[_\-]?key|auth[_\-]?token|access[_\-]?token|client[_\-]?secret)'
     r'\s*[=:\"\']\s*[A-Za-z0-9\-_.]{16,}',
    re.IGNORECASE,
)

# Bare hostnames / FQDNs (no scheme).  Excludes plain IPs (those hit _RE_IP).
# Must have at least one dot, a known-length TLD (2–24 chars), optional port.
_RE_DOMAINS = re.compile(
    r'^(?!.*://)(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+[a-zA-Z]{2,24}'
    r'(?::\d{1,5})?$',
)

# Common Linux / shell commands (first token matches a known binary)
_LINUX_COMMANDS = {
    "ls", "cd", "pwd", "rm", "cp", "mv", "cat", "echo", "grep", "find",
    "chmod", "chown", "chroot", "su", "sudo", "sh", "bash", "dash", "zsh",
    "ps", "kill", "killall", "top", "df", "du", "mount", "umount", "dd",
    "nc", "netcat", "curl", "wget", "ssh", "scp", "sftp", "ftp", "telnet",
    "ping", "ifconfig", "ip", "iptables", "nmap", "tcpdump", "awk", "sed",
    "cut", "tr", "sort", "uniq", "wc", "head", "tail", "tee", "xargs",
    "tar", "gzip", "gunzip", "zip", "unzip", "base64", "od", "xxd",
    "python", "python3", "perl", "ruby", "php", "node", "java",
    "am", "pm", "dumpsys", "logcat", "adb",          # Android-specific
}
 
_RE_LINUX_CMD = re.compile(
    r'^([a-z][a-z0-9_\-]*)(?:\s|$)', 
    re.IGNORECASE
)