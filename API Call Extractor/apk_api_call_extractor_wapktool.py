import os
import subprocess
import re
from pathlib import Path

def check_apktool() -> bool:
    """Ensure apktool is installed."""
    try:
        subprocess.run(["apktool", "--version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("apktool not found. Installing...")
        subprocess.run(["sudo", "apt-get", "update"], check=True)
        subprocess.run(["sudo", "apt-get", "install", "-y", "apktool"], check=True)
        return True
    return False

def decompile_apk(apk_path : Path, output_dir: Path) -> bool:
    """Decompile APK using apktool."""
    print(f"Decompiling {apk_path} to {output_dir}...")
    try:
        subprocess.run(["apktool", "d", apk_path, "-f", "-o", output_dir], check=True)
        print("Decompilation successful.")
    except subprocess.CalledProcessError as e:
        print(f"Decompilation failed: {e}")
        return False
    return True

def extract_api_calls(apk_path, apk_smali_dir):
    """Extract potential API calls from smali files."""
    api_calls = set()
    
    # Regex to match invoke instructions in smali
    invoke_pattern = re.compile(r'invoke-(?:virtual|direct|static|interface)\s+{[^}]*},\s*(L[a-zA-Z0-9/$]+;)->([a-zA-Z0-9_]+)\(')

    print(f"Analyzing {apk_path}:smali files for API calls...")
    for root, _, files in os.walk(apk_smali_dir):
        for file in files:
            if file.endswith(".smali"):
                file_path = Path(root) / file
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    matches = invoke_pattern.finditer(content)
                    for match in matches:
                        class_name = match.group(1).replace("/", ".")
                        method_name = match.group(2)
                        # Filter for Android API classes (basic heuristic)
                        if class_name.startswith("Landroid") or class_name.startswith("Ljava"):
                            api_calls.add(f"{class_name}->{method_name}")

    return sorted(api_calls)

def main():
    apk_path = Path("apks/cybersecurity-dev.apk")
    filename = Path(apk_path).stem
    output_dir = f"decompiled_apk_{filename}"
    
    # Ensure apktool is available
    if not check_apktool():
        print(f"apktool couldn't available")
        return

    # Decompile the APK
    if not decompile_apk(apk_path, output_dir):
        print(f"getting error with decompile_apk")
        return

    # Extract API calls
    api_calls = extract_api_calls(apk_path, output_dir)

    # Save results
    output_file = f"{filename}_api_calls.txt"
    with open(output_file, "w", encoding="utf-8") as f:
        for call in api_calls:
            f.write(f"{call}\n")
    
    print(f"Found {len(api_calls)} potential API calls. Results saved to {output_file}.")

    subprocess.run(["rm", "-rf", output_dir])
    print(f"{output_dir}: Decompiled files removed.")
    
if __name__ == "__main__":
    main()