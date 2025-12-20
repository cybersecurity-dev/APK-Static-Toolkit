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

