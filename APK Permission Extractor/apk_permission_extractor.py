import os
import subprocess
import json

import xml.etree.ElementTree as ET

def extract_permissions(apk_path):
    try:
        # Run aapt command to dump permissions
        result = subprocess.run(['aapt', 'dump', 'permissions', apk_path], 
                              capture_output=True, 
                              text=True, 
                              check=True)
        
        # Process the output to get permissions
        permissions = []
        for line in result.stdout.split('\n'):
            if line.startswith('uses-permission:'):
                permission = line.split('name=')[1].strip("'")
                permissions.append(permission)
        
        return permissions
    
    except subprocess.CalledProcessError as e:
        print(f"Error running aapt: {e}")
        return []
    except FileNotFoundError:
        print("aapt tool not found. Please install Android SDK build-tools")
        return []

def save_to_json(permissions, output_file):
    try:
        with open(output_file, 'w') as f:
            json.dump({"permissions": permissions}, f, indent=4)
        print(f"Permissions saved to {output_file}")
    except Exception as e:
        print(f"Error saving to JSON: {e}")

def save_to_xml(permissions, output_file):
    try:
        root = ET.Element("permissions")
        for perm in permissions:
            perm_elem = ET.SubElement(root, "permission")
            perm_elem.text = perm
        
        tree = ET.ElementTree(root)
        ET.indent(tree, space="    ")  # Pretty print
        tree.write(output_file, encoding='utf-8', xml_declaration=True)
        print(f"Permissions saved to {output_file}")
    except Exception as e:
        print(f"Error saving to XML: {e}")

def main():
    # Check if aapt is available
    if not subprocess.run(['which', 'aapt'], capture_output=True).stdout:
        print("Please install Android SDK build-tools and ensure aapt is in your PATH")
        return

    # Get APK file path from user
    apk_path = input("Enter the path to the APK file: ")
    
    # Verify file exists and is an APK
    if not os.path.exists(apk_path) or not apk_path.endswith('.apk'):
        print("Invalid APK file path")
        return

    # Extract permissions
    permissions = extract_permissions(apk_path)
    
    if not permissions:
        print("No permissions found or extraction failed")
        return

    # filename
    base_name = os.path.splitext(apk_path)[0]
    json_output = f"{base_name}_permissions.json"
    xml_output = f"{base_name}_permissions.xml"

    # Save to both formats
    save_to_json(permissions, json_output)
    save_to_xml(permissions, xml_output)

if __name__ == "__main__":
    main()