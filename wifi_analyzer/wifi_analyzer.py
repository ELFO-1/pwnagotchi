#!/usr/bin/env python3
"""
WiFi Capture File Analyzer
Checks .cap/.pcap files for compatibility with aircrack-ng, hashcat, and cowpatty
"""

import os
import subprocess
import re
import argparse
from pathlib import Path

def run_command(cmd):
    """Run a command and return output, error, and return code"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out", 1
    except Exception as e:
        return "", str(e), 1

def check_aircrack(file_path):
    """Check if file is valid for aircrack-ng"""
    cmd = f'aircrack-ng "{file_path}"'
    stdout, stderr, returncode = run_command(cmd)

    # Look for handshake count in output
    handshake_match = re.search(r'WPA.*\((\d+)\s+handshake', stdout)
    if handshake_match and int(handshake_match.group(1)) > 0:
        # Extract BSSID for command
        bssid_match = re.search(r'([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})', stdout)
        bssid = bssid_match.group(1) if bssid_match else "BSSID_HERE"
        return True, f'aircrack-ng -w wordlist.txt -b {bssid} "{file_path}"'
    return False, None

def check_hashcat(file_path):
    """Check if file can be converted for hashcat"""
    # Try to convert to hashcat format
    temp_hc = f"{file_path}.hc22000"
    cmd = f'hcxpcapngtool -o "{temp_hc}" "{file_path}"'
    stdout, stderr, returncode = run_command(cmd)

    if returncode == 0 and os.path.exists(temp_hc):
        # Check if the converted file has content
        try:
            with open(temp_hc, 'r') as f:
                content = f.read().strip()
            if content:
                hashcat_cmd = f'hashcat -m 22000 "{temp_hc}" wordlist.txt'
                return True, hashcat_cmd
        except:
            pass
        finally:
            # Clean up temp file
            if os.path.exists(temp_hc):
                os.remove(temp_hc)

    return False, None

def check_cowpatty(file_path):
    """Check if file is valid for cowpatty"""
    cmd = f'cowpatty -r "{file_path}" -f /dev/null'
    stdout, stderr, returncode = run_command(cmd)

    # Cowpatty will complain about missing dictionary but if file is valid, it won't error about the cap file
    if "invalid capture file" not in stderr.lower() and "no valid packets" not in stderr.lower():
        if "specify dictionary file" in stderr.lower() or returncode == 1:
            return True, f'cowpatty -r "{file_path}" -f wordlist.txt -s ESSID_HERE'
    return False, None

def get_file_info(file_path):
    """Get basic info about the capture file"""
    cmd = f'capinfos "{file_path}"'
    stdout, stderr, returncode = run_command(cmd)

    info = {}
    if returncode == 0:
        # Extract packet count
        packet_match = re.search(r'Number of packets:\s+(\d+)', stdout)
        if packet_match:
            info['packets'] = int(packet_match.group(1))

        # Extract file size
        size_match = re.search(r'File size:\s+(\d+)', stdout)
        if size_match:
            info['size'] = int(size_match.group(1))

    return info

def analyze_capture_files(folder_path, delete_unusable=False, verbose=False):
    """Analyze all capture files in a folder"""

    print("🔍 WiFi Capture File Analyzer")
    print("=" * 50)

    # Find all .cap and .pcap files
    folder = Path(folder_path)
    cap_files = list(folder.glob("*.cap")) + list(folder.glob("*.pcap"))

    if not cap_files:
        print(f"❌ No .cap or .pcap files found in {folder_path}")
        return

    print(f"📁 Found {len(cap_files)} capture files in {folder_path}")
    print()

    valid_files = []
    invalid_files = []

    for file_path in cap_files:
        print(f"🔎 Analyzing: {file_path.name}")

        # Get basic file info
        if verbose:
            info = get_file_info(str(file_path))
            if info:
                print(f"   📊 Packets: {info.get('packets', 'Unknown')}, Size: {info.get('size', 'Unknown')} bytes")

        # Check with different tools
        tools_working = []
        commands = []

        # Check aircrack-ng
        aircrack_valid, aircrack_cmd = check_aircrack(str(file_path))
        if aircrack_valid:
            tools_working.append("aircrack-ng")
            commands.append(f"   💻 aircrack-ng: {aircrack_cmd}")

        # Check hashcat (only if hcxpcapngtool is available)
        if subprocess.run("which hcxpcapngtool", shell=True, capture_output=True).returncode == 0:
            hashcat_valid, hashcat_cmd = check_hashcat(str(file_path))
            if hashcat_valid:
                tools_working.append("hashcat")
                commands.append(f"   💻 hashcat: {hashcat_cmd}")

        # Check cowpatty
        if subprocess.run("which cowpatty", shell=True, capture_output=True).returncode == 0:
            cowpatty_valid, cowpatty_cmd = check_cowpatty(str(file_path))
            if cowpatty_valid:
                tools_working.append("cowpatty")
                commands.append(f"   💻 cowpatty: {cowpatty_cmd}")

        # Report results
        if tools_working:
            print(f"   ✅ VALID - Compatible with: {', '.join(tools_working)}")
            for cmd in commands:
                print(cmd)
            valid_files.append(file_path)
        else:
            print(f"   ❌ INVALID - No tools can use this file")
            invalid_files.append(file_path)

        print()

    # Summary
    print("📋 SUMMARY")
    print("=" * 50)
    print(f"✅ Valid files: {len(valid_files)}")
    print(f"❌ Invalid files: {len(invalid_files)}")

    if valid_files:
        print("\n🎯 VALID FILES:")
        for f in valid_files:
            print(f"   • {f.name}")

    if invalid_files:
        print(f"\n🗑️  INVALID FILES:")
        for f in invalid_files:
            print(f"   • {f.name}")

        if delete_unusable:
            print(f"\n⚠️  DELETING {len(invalid_files)} invalid files...")
            for f in invalid_files:
                try:
                    f.unlink()
                    print(f"   🗑️  Deleted: {f.name}")
                except Exception as e:
                    print(f"   ❌ Failed to delete {f.name}: {e}")
        else:
            print(f"\n💡 To delete invalid files, run with --delete flag")

def main():
    parser = argparse.ArgumentParser(description="Analyze WiFi capture files for compatibility with cracking tools")
    parser.add_argument("folder", help="Folder containing .cap/.pcap files")
    parser.add_argument("--delete", action="store_true", help="Delete unusable files")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed file information")

    args = parser.parse_args()

    if not os.path.exists(args.folder):
        print(f"❌ Error: Folder '{args.folder}' does not exist")
        return

    analyze_capture_files(args.folder, args.delete, args.verbose)

if __name__ == "__main__":
    main()
