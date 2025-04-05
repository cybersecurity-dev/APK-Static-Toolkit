import sys
from pathlib import Path
import zipfile
import pyaxmlparser

# Android API level to version mapping
API_TO_VERSION = {
    1: "1.0", 2: "1.1", 3: "1.5", 4: "1.6", 5: "2.0", 6: "2.0.1",
    7: "2.1", 8: "2.2", 9: "2.3", 10: "2.3.3", 11: "3.0", 12: "3.1",
    13: "3.2", 14: "4.0", 15: "4.0.3", 16: "4.1", 17: "4.2", 18: "4.3",
    19: "4.4", 20: "4.4W", 21: "5.0", 22: "5.1", 23: "6.0", 24: "7.0",
    25: "7.1", 26: "8.0", 27: "8.1", 28: "9", 29: "10", 30: "11",
    31: "12", 32: "12L", 33: "13", 34: "14"
}

def get_min_sdk_from_apk(apk_path):
    """Extract minimum SDK version from APK's AndroidManifest.xml using pyaxmlparser"""
    try:
        apk_path = Path(apk_path)
        if not apk_path.exists():
            return None, None, "APK file does not exist"
        if not apk_path.is_file() or apk_path.suffix.lower() != '.apk':
            return None, None, "Path is not an APK file"

        # Use pyaxmlparser to parse the APK directly
        apk = pyaxmlparser.APK(apk_path)
        min_sdk = apk.get_min_sdk_version()
        
        if min_sdk:
            min_sdk = int(min_sdk)
            version = API_TO_VERSION.get(min_sdk, "Unknown")
            return min_sdk, version, f"Minimum SDK: API {min_sdk} (Android {version})"
        return 1, "1.0", "No minSdkVersion specified, assuming API 1 (Android 1.0)"

    except zipfile.BadZipFile:
        return None, None, "Invalid APK file format"
    except Exception as e:
        return None, None, f"Error during analysis: {str(e)}"

def main():
    if len(sys.argv) < 2:
        print("Usage: python check_minimum_required_android_version_pyaxmlparser.py <path_to_apk>")
        sys.exit(1)
    
    apk_path = sys.argv[1]
    min_sdk, version, message = get_min_sdk_from_apk(apk_path)
    
    print(f"APK: {apk_path}")
    if min_sdk is not None:
        print(f"Minimum SDK Version: API {min_sdk}")
        print(f"Android Version: {version}")
    print(f"Message: {message}")

if __name__ == "__main__":
    main()