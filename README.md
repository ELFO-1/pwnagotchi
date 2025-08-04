# pwnagotchi
my pwnagotchi setup  (use at u own risk .. bec its made for myself)


<img width="1926" height="1440" alt="grafik" src="https://github.com/user-attachments/assets/6313ce81-98ba-4fea-a443-324564c6c2fc" />

img from https://github.com/jayofelony/pwnagotchi
wiki : https://github.com/jayofelony/pwnagotchi/wiki

thanks to jayofelony for the great work

custom faces from there :  https://github.com/sumeshi/PWNAGOTCHI-CUSTOM-FACES-MOD/blob/main/README.md

for use the 3.5 LCD display on the rasp 3b+

Open the "config.txt" file under the boot directory, comment out "dtoverlay=vc4-kms-v3d", and add the following at the end of [all]: 

[all]
dtparam=spi=on
dtoverlay=waveshare35a

hdmi_force_hotplug=1
max_usb_current=1
hdmi_group=2
hdmi_mode=1
hdmi_mode=87
hdmi_cvt 480 320 60 6 0 0 0
hdmi_drive=2
display_rotate=0

in the config.toml add this :

ui.display.enabled = true
ui.display.type = "waveshare35lcd"
ui.display.color = "white"
ui.display.fps = 1
ui.display.framebuffer = "/dev/fb1"


on ssh enter this comands :

sudo apt-get install libraspberrypi-dev raspberrypi-kernel-headers

sudo rm -rf LCD-show

git clone https://github.com/goodtft/LCD-show.git
chmod -R 755 LCD-show
cd LCD-show/
sudo ./LCD35-show 

++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

external wifi ( disable bluetooth also )

sudo nano /boot/firmware/config.txt
uncomment or add under [all] 
dtoverlay=disable-wifi

++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
bluethooth

bluetoothctl

Then:

scan on
pair <your-phone-mac>
trust <your-phone-mac>


++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++


and disable the plugin fix_services bec its only for internal
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

for external wifi :
sudo nano /boot/firmware/config.txt
remove # from #dtoverlay=disable-wifi
if not there then add under all :

for the Alfa Awus036ACS ( i get from here : https://github.com/lwfinger/rtw88 )

sudo apt update
sudo apt install -y raspberrypi-kernel-headers build-essential git
cd /
git clone https://github.com/lwfinger/rtw88
cd rtw88
sudo dkms install $PWD
sudo make install_fw


#####################################################################################################


wifi_handshake_analyzer
*************************
i made so i see what tool i can see what handshakes are valid and it showes me the command so i can copy paste and only change the path to the wordlist i want use  :)
chmod +x wifi_handshake_analyzer.py
./wifi_handshake_analyzer.py /path/to/your/captures/

Basic check (no deletion):
usage python3 wifi_handshake_analyzer.py /path to your Handshake folder 
( example :  python3 wifi_handshake_analyzer.py /home/user/handshakes/ )

if u want automatic delete the unvalid handshakes then use 

Check and delete unusable files:
python3 wifi_handshake_analyzer.py /path to your Handshake folder --delete   
( example :  python3 wifi_handshake_analyzer.py /home/user/handshakes/ --delete )

Verbose mode (shows packet counts and file sizes):
python3 wifi_handshake_analyzer.py /path to your Handshake folder --verbose   
( example :  python3 wifi_handshake_analyzer.py /home/user/handshakes/ --verbose )

Example Output:

🔍 WiFi Capture File Analyzer
==================================================
📁 Found 5 capture files in /home/user/handshakes

🔎 Analyzing: network1.pcap
   ✅ VALID - Compatible with: aircrack-ng, hashcat
   💻 aircrack-ng: aircrack-ng -w wordlist.txt -b AA:BB:CC:DD:EE:FF "network1.pcap"
   💻 hashcat: hashcat -m 22000 "network1.pcap.hc22000" wordlist.txt

🔎 Analyzing: broken.cap
   ❌ INVALID - No tools can use this file

📋 SUMMARY
==================================================
✅ Valid files: 1
❌ Invalid files: 1

wordlist.txt change to the path were your wordlist is

Verbose mode (shows packet counts and file sizes):
