import os
import sys
import zipfile
from pathlib import Path

def is_ndk_apk(apk_path):
    """
    Check if the given APK file contains NDK components
    Returns: tuple (bool, str) - (is_ndk, detection_reason)
    """
    # Common NDK-related indicators in APK
    ndk_indicators = [
        # Native library directories
        'lib/armeabi',
        'lib/armeabi-v7a',
        'lib/arm64-v8a',
        'lib/x86',
        'lib/x86_64',
        # Common native library extensions
        '.so',
    ]
    
    try:
        # Validate APK path
        apk_path = Path(apk_path)
        if not apk_path.exists():
            return False, "APK file does not exist"
        if not apk_path.is_file() or apk_path.suffix.lower() != '.apk':
            return False, "Path is not an APK file"

        # Open APK as ZIP file
        with zipfile.ZipFile(apk_path, 'r') as apk:
            # Get list of all files in APK
            file_list = apk.namelist()
            
            # Check for native libraries
            for file_path in file_list:
                file_lower = file_path.lower()
                
                # Check for native library directories
                if any(indicator in file_lower for indicator in ndk_indicators):
                    return True, f"Found native library directory: {file_path}"
                
                # Check for .so files in lib directory
                if file_lower.startswith('lib/') and file_lower.endswith('.so'):
                    return True, f"Found native library: {file_path}"

            # If no native libraries found
            return False, "No NDK components detected in APK"

    except zipfile.BadZipFile:
        return False, "Invalid APK file format"
    except Exception as e:
        return False, f"Error during analysis: {str(e)}"

def analyze_project_or_apk(path):
    """
    Determine if path is a project directory or APK and analyze accordingly
    """
    path = Path(path)
    
    if path.is_file() and path.suffix.lower() == '.apk':
        return is_ndk_apk(path)
    else:
        return False, "Not APK file"

def main():
    # Get path from command line argument or use current directory

    if len(sys.argv) > 1:
        path = sys.argv[1]
    else:
    	print("Usage: python3 check_ndk_based_apk.py <path_to_apk>")
        sys.exit(1)

    # Analyze the path
    is_ndk, reason = analyze_project_or_apk(path)
    
    # Print results
    print(f"Path: {path}")
    print(f"Is NDK-based: {is_ndk}")
    print(f"Reason: {reason}")

if __name__ == "__main__":
    main()