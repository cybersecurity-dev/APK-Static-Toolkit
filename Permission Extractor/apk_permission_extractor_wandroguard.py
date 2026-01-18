import json
import os
import sys
import glob

import xml.etree.ElementTree as ET
from androguard.core.apk import APK

def extract_permissions_wandroguard(apk_path):
    """Extract permissions from an APK file using androguard"""
    try:
        # Load the APK
        apk = APK(apk_path)
        # Get permissions directly from androguard
        permissions = apk.get_permissions()
        return permissions
    
    except Exception as e:
        print(f"Error extracting permissions from {apk_path}: {e}")
        return []

def save_to_json(permissions, output_file):
    try:
        os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
        with open(output_file, 'w') as f:
            json.dump({"permissions": permissions}, f, indent=4)
        print(f"Permissions saved to {output_file}")
    except Exception as e:
        print(f"Error saving to JSON: {e}")

def save_to_xml(permissions, output_file):
    try:
        os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
        root = ET.Element("permissions")
        for perm in permissions:
            perm_elem = ET.SubElement(root, "permission")
            perm_elem.text = perm
        
        tree = ET.ElementTree(root)
        ET.indent(tree, space="    ")
        tree.write(output_file, encoding='utf-8', xml_declaration=True)
        print(f"Permissions saved to {output_file}")
    except Exception as e:
        print(f"Error saving to XML: {e}")

def process_apk(apk_path, output_dir='./'):
    """Process a single APK file"""
    permissions = extract_permissions_wandroguard(apk_path)
    
    if not permissions:
        print(f"No permissions found or extraction failed for {apk_path}")
        return

    # Determine output path
    if output_dir:
        base_name = os.path.splitext(os.path.basename(apk_path))[0]
        output_base = os.path.join(output_dir, base_name)
    else:
        input_dir = os.path.dirname(apk_path) or '.'  # Use current dir if no dir in path
        base_name = os.path.splitext(os.path.basename(apk_path))[0]
        output_base = os.path.join(input_dir, base_name)

    json_output = f"{output_base}_permissions.json"
    xml_output = f"{output_base}_permissions.xml"

    save_to_json(permissions, json_output)
    save_to_xml(permissions, xml_output)

def main():
    # Check command line arguments
    if len(sys.argv) != 2:
        print("Usage: python3 apk_permission_extractor_wandroguard.py <apk_file_or_directory>")
        print("Example: python3 apk_permission_extractor_wandroguard.py app.apk")
        print("Example: python3 apk_permission_extractor_wandroguard.py /path/to/apks/")
        sys.exit(1)

    input_path = sys.argv[1]

    # Handle single file
    if os.path.isfile(input_path) and input_path.endswith('.apk'):
        process_apk(input_path)
    
    # Handle directory
    elif os.path.isdir(input_path):
        # Create output directory with _permissions suffix
        input_dir = input_path.rstrip('/')  # Remove trailing slash if present
        output_dir = f"{input_dir}_permissions"
        
        apk_files = glob.glob(os.path.join(input_path, '*.apk'))
        
        if not apk_files:
            print(f"No APK files found in {input_path}")
            sys.exit(1)

        for apk_file in apk_files:
            process_apk(apk_file, output_dir)
    
    else:
        print("Invalid input: must be an APK file or a directory")
        sys.exit(1)

if __name__ == "__main__":
    main()