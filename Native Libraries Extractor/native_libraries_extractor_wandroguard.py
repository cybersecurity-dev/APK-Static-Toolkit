import json
import os
import sys
import glob
import argparse

import xml.etree.ElementTree as ET

try:
    from androguard.core.apk import APK
except ImportError:
    import subprocess
    import sys
    print("Androguard not found. Installing...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "androguard"])
    from androguard.core.apk import APK

def extract_native_libs_wandroguard(apk_path):
    native_libs = []
    
    try:
        # Load the APK using Androguard
        apk = APK(apk_path)
        
        # Get all files in the APK
        files = apk.get_files()
        
        # Filter for native libraries in the 'lib/' directory
        for file_path in files:
            if file_path.startswith('lib/') and file_path.endswith('.so'):
                lib_name = os.path.basename(file_path)
                native_libs.append(lib_name)
    except Exception as e:
        print(f"Error reading {apk_path} with Androguard: {e}")
        return []
    
    return native_libs

def save_to_json(libs, output_file):
    data = {"native_libraries": libs}
    try:
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"Saved JSON to {output_file}")
    except Exception as e:
        print(f"Error saving JSON to {output_file}: {e}")

def save_to_xml(libs, output_file):
    root = ET.Element("native_libraries")
    
    for lib in libs:
        lib_elem = ET.SubElement(root, "library")
        lib_elem.text = lib
    
    tree = ET.ElementTree(root)
    try:
        ET.indent(tree, space="    ")
        tree.write(output_file, encoding='utf-8', xml_declaration=True)
        print(f"Saved XML to {output_file}")
    except Exception as e:
        print(f"Error saving XML to {output_file}: {e}")

def process_apk(apk_path, output_dir, verbose=False):
    """
    Process a single APK file and save results in the output directory.
    """
    apk_name = os.path.splitext(os.path.basename(apk_path))[0]
    native_libs = extract_native_libs_wandroguard(apk_path)
    
    if not native_libs:
        print(f"No native libraries found in {apk_path}")
        return
    
    if verbose:
        print(f"Found native libraries in {apk_path}: {native_libs}")
    
    json_output = os.path.join(output_dir, f"{apk_name}_libs.json")
    xml_output = os.path.join(output_dir, f"{apk_name}_libs.xml")
    
    save_to_json(native_libs, json_output)
    save_to_xml(native_libs, xml_output)

def main():
    parser = argparse.ArgumentParser(description="Extract native libraries from APK files.")
    parser.add_argument("path", help="Path to an APK file or directory containing APKs")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print verbose output (list of libraries)")
    
    # Parse arguments
    args = parser.parse_args()
    input_path = args.path
    verbose = args.verbose
    
    if not os.path.exists(input_path):
        print(f"Error: {input_path} does not exist!")
        sys.exit(1)
    
    # If it's a single APK file
    if os.path.isfile(input_path) and input_path.endswith('.apk'):
        output_dir = os.path.dirname(input_path) or '.'
        process_apk(input_path, output_dir, verbose)
    
    # If it's a directory
    elif os.path.isdir(input_path):
        # Create apks_libs directory
        output_dir = os.path.join(input_path, "apks_libs")
        os.makedirs(output_dir, exist_ok=True)
        
        # Find all APK files in the directory
        apk_files = glob.glob(os.path.join(input_path, "*.apk"))
        if not apk_files:
            print(f"No APK files found in {input_path}")
            sys.exit(1)
        
        # Process each APK
        for apk_file in apk_files:
            process_apk(apk_file, output_dir, verbose)
    
    else:
        print(f"Error: {input_path} is neither a valid APK file nor a directory!")
        sys.exit(1)

if __name__ == "__main__":
    main()
