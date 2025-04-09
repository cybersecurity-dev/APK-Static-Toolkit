import subprocess
import json
import os
import sys
import glob
import xml.etree.ElementTree as ET

def extract_permissions(apk_path):
    """Extract permissions from an APK file using aapt"""
    try:
        result = subprocess.run(['aapt', 'dump', 'permissions', apk_path], 
                              capture_output=True, 
                              text=True, 
                              check=True)
        
        permissions = []
        for line in result.stdout.split('\n'):
            if line.startswith('uses-permission:'):
                permission = line.split('name=')[1].strip("'")
                permissions.append(permission)
        
        return permissions
    
    except subprocess.CalledProcessError as e:
        print(f"Error running aapt for {apk_path}: {e}")
        return []
    except FileNotFoundError:
        print("aapt tool not found. Please install Android SDK build-tools")
        return []

def save_to_json(permissions, output_file):
    try:
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, 'w') as f:
            json.dump({"permissions": permissions}, f, indent=4)
        print(f"Permissions saved to {output_file}")
    except Exception as e:
        print(f"Error saving to JSON: {e}")

def save_to_xml(permissions, output_file):
    try:
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
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
    permissions = extract_permissions(apk_path)
    
    if not permissions:
        print(f"No permissions found or extraction failed for {apk_path}")
        return

    # Determine output path
    if output_dir:
        base_name = os.path.splitext(os.path.basename(apk_path))[0]
        output_base = os.path.join(output_dir, base_name)
    else:
        base_name = os.path.splitext(apk_path)[0]
        output_base = base_name

    json_output = f"{output_base}_permissions.json"
    xml_output = f"{output_base}_permissions.xml"

    save_to_json(permissions, json_output)
    save_to_xml(permissions, xml_output)

def main():
    # Check if aapt is available
    if not subprocess.run(['which', 'aapt'], capture_output=True).stdout:
        print("Please install Android SDK build-tools and ensure aapt is in your PATH")
        return

    if len(sys.argv) != 2:
        print("Usage: python3 apk_permission_extractor.py <apk_file_or_directory>")
        print("Example: python3 apk_permission_extractor.py app.apk")
        print("Example: python3 apk_permission_extractor.py /path/to/apks/")
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