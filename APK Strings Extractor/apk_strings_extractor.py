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


def extract_important_strings_from_apk(apk_path: Path) -> dict:
    patterns = {
        'urls': re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+'),
        'ips': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
        'emails': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        'domains': re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'),
        #'api_keys': re.compile(r'(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|secret[_-]?key)[\s:=]+["\']?([a-zA-Z0-9_\-]{20,})["\']?', re.IGNORECASE),
        'file_paths': re.compile(r'(?:/[a-zA-Z0-9_.-]+)+/?|(?:[A-Z]:\\(?:[^\\\s]+\\)*[^\\\s]+)'),
        #'base64': re.compile(r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'),
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
