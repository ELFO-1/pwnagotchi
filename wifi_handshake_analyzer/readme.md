# wifi_handshake_analyzer

i made so i see what tool i can see what handshakes are valid and it showes me the command so i can copy paste and only change the path to the wordlist i want use :) chmod +x wifi_handshake_analyzer.py ./wifi_handshake_analyzer.py /path/to/your/captures/

Basic check (no deletion): usage python3 wifi_handshake_analyzer.py /path to your Handshake folder ( example : python3 wifi_handshake_analyzer.py /home/user/handshakes/ )

if u want automatic delete the unvalid handshakes then use

Check and delete unusable files: python3 wifi_handshake_analyzer.py /path to your Handshake folder --delete
( example : python3 wifi_handshake_analyzer.py /home/user/handshakes/ --delete )

Verbose mode (shows packet counts and file sizes): python3 wifi_handshake_analyzer.py /path to your Handshake folder --verbose
( example : python3 wifi_handshake_analyzer.py /home/user/handshakes/ --verbose )

Example Output:
🔍 WiFi Capture File Analyzer

📁 Found 5 capture files in /home/user/handshakes

🔎 Analyzing: network1.pcap ✅ VALID - Compatible with: aircrack-ng, hashcat 💻 aircrack-ng: aircrack-ng -w wordlist.txt -b AA:BB:CC:DD:EE:FF "network1.pcap" 💻 hashcat: hashcat -m 22000 "network1.pcap.hc22000" wordlist.txt

🔎 Analyzing: broken.cap ❌ INVALID - No tools can use this file
📋 SUMMARY

✅ Valid files: 1 ❌ Invalid files: 1

wordlist.txt change to the path were your wordlist is

Verbose mode (shows packet counts and file sizes):
