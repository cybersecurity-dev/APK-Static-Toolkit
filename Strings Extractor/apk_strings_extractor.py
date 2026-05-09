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





def is_file_path(s: str) -> bool:
    """Return True if the string looks like a Unix or Windows file path."""
    return bool(_RE_FILE_PATH.match(s.strip()))


def is_url(s: str) -> bool:
    """Return True if the string looks like a URL."""
    return bool(_RE_URL.match(s.strip()))
 
 
def is_ip_address(s: str) -> bool:
    """Return True if the string is an IPv4 or IPv6 address (with optional port)."""
    stripped = s.strip()
    return bool(_RE_IP.match(stripped) or _RE_IPV6.match(stripped))
 
 
def is_linux_command(s: str) -> bool:
    """Return True if the string starts with a known Linux/shell command token."""
    stripped = s.strip()
    m = _RE_LINUX_CMD.match(stripped)
    if not m:
        return False
    return m.group(1).lower() in _LINUX_COMMANDS
 
 
def is_crypto_key(s: str) -> bool:
    """
    Return True if the string looks like a cryptographic key or certificate.
    Matches PEM blocks, raw hex keys (128-512 bit), and SSH public-key blobs.
    """
    return bool(_RE_CRYPTO_KEYS.search(s.strip()))
 
 
def is_base64(s: str) -> bool:
    """Return True if the string appears to be a Base64-encoded payload."""
    stripped = s.strip()
    if len(stripped) < 16:
        return False
    
    # Defer to is_api_key for vendor-prefixed tokens (e.g. AIzaSy…, AKIA…)
    if is_api_key(stripped):
        return False
    if not _RE_BASE64.match(stripped):
        return False
    
    # Reject strings that are 100 % hex digits — those are hashes / raw keys
    # already caught by is_crypto_key.
    if re.fullmatch(r'[0-9a-fA-F]+', stripped):
        return False
    return True
 
 
def is_api_key(s: str) -> bool:
    """Return True if the string matches a known API / secret-key format."""
    return bool(_RE_API_KEYS.search(s.strip()))
 
def is_domain(s: str) -> bool:
    """
    Return True if the string is a bare domain name or FQDN (no URL scheme).
    Excludes:
      - Plain IP addresses (caught by is_ip_address).
      - Strings that already match a URL scheme.
      - Java/Android package names (e.g. com.google.android.gms) — those have
        lowercase labels separated by dots with no recognised network TLD pattern
        and often contain mixed-case segments like 'BuildConfig'.
    """
    stripped = s.strip()
    if is_ip_address(stripped) or is_url(stripped):
        return False
    if not _RE_DOMAINS.match(stripped):
        return False
    
    # Reject Java package names: all-lowercase dotted segments where any label
    # looks like a Java identifier (contains uppercase mid-word or underscores)
    # or the TLD is not a real network suffix (e.g. ".gms", ".DEBUG").
    labels = stripped.split(".")
    tld = labels[-1].split(":")[0]   # strip optional port from last label
    
    # If the TLD is ALL-CAPS or mixed-case camelCase it's almost certainly
    # a class/package name, not a real domain.
    if re.search(r'[A-Z]', tld):
        return False
    
    # If any non-first label starts with a digit it could be a version string.
    # Real FQDNs do allow digits but combined with the other checks this helps.
    # Require the TLD to be alphabetic only (no digits).
    if not re.fullmatch(r'[a-zA-Z]{2,24}', tld):
        return False
    return True

#---------------------------------------------------------------------------------------------------------------------

def _extract_strings_from_bytes(data: bytes, min_len: int = 4, max_len: int = 300) -> list[str]:
    pattern = re.compile(rb'[\x20-\x7e]{' + str(min_len).encode() + rb',' + str(max_len).encode() + rb'}')
    return [s.decode("ascii", errors="ignore") for s in pattern.findall(data)]

def _extract_strings_from_apk(apk_path: Path, 
                             min_length: int = 5,
                             max_length: int = 300,
                             extensions: tuple[str, ...] = (".dex", ".xml", ".json", ".txt", ".js", ".smali", "") ) \
    -> List[str] | None:
    
    if not os.path.isfile(apk_path):
        raise FileNotFoundError(f"APK not found: {apk_path}")
 
    seen: set[str] = set()
    results: list[str] = []
 
    with zipfile.ZipFile(apk_path, "r") as apk:
        for entry in apk.infolist():
            name_lower = entry.filename.lower()
            _, ext = os.path.splitext(name_lower)
 
            if extensions and ext not in extensions:
                continue
 
            try:
                data = apk.read(entry.filename)
            except Exception:
                continue
 
            for s in _extract_strings_from_bytes(data, min_length, max_length):
                if s not in seen:
                    seen.add(s)
                    results.append(s)
 
    return results

#---------------------------------------------------------------------------------------------------------------------

CATEGORY_CRYPTO_KEY   = "crypto_key"
CATEGORY_API_KEY      = "api_key"
CATEGORY_BASE64       = "base64"
CATEGORY_IP           = "ip_address"
CATEGORY_DOMAIN       = "domain"
CATEGORY_URL          = "url"
CATEGORY_FILE_PATH    = "file_path"
CATEGORY_LINUX_CMD    = "linux_command"
CATEGORY_OTHER        = "other"

CATEGORY_ORDER = [CATEGORY_CRYPTO_KEY,
                  CATEGORY_API_KEY,
                  CATEGORY_BASE64,
                  CATEGORY_IP,
                  CATEGORY_DOMAIN,
                  CATEGORY_URL,
                  CATEGORY_FILE_PATH,
                  CATEGORY_LINUX_CMD,
                  CATEGORY_OTHER]

def categorize_string(s: str) -> str:
    if is_crypto_key(s):
        return CATEGORY_CRYPTO_KEY
    if is_api_key(s):
        return CATEGORY_API_KEY
    if is_base64(s):
        return CATEGORY_BASE64
    if is_ip_address(s):
        return CATEGORY_IP
    if is_domain(s):
        return CATEGORY_DOMAIN
    if is_url(s):
        return CATEGORY_URL
    if is_file_path(s):
        return CATEGORY_FILE_PATH
    if is_linux_command(s):
        return CATEGORY_LINUX_CMD
    return CATEGORY_OTHER

def categorize_strings(strings: list[str]) -> dict[str, list[str]]:
    buckets: dict[str, list[str]] = defaultdict(list)
    for s in strings:
        buckets[categorize_string(s)].append(s)
 
    # Return in a consistent order
    return {cat: buckets[cat] for cat in CATEGORY_ORDER}

#---------------------------------------------------------------------------------------------------------------------

def extract_string_and_categorize_from_apk(apk_path: Path,
                                           min_length: int = 5,
                                           max_length: int = 300) -> dict[str, list[str]]:
    
    strings = _extract_strings_from_apk(apk_path, min_len=min_len, max_len=max_len)
    return categorize_strings(strings)

#---------------------------------------------------------------------------------------------------------------------