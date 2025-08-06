# pwnagotchi
my pwnagotchi setup rasp 3b+ with a 3.5 LCD display und custom Face  (use at u own risk .. bec its made for myself)


<img width="1926" height="1440" alt="grafik" src="https://github.com/user-attachments/assets/6313ce81-98ba-4fea-a443-324564c6c2fc" />

```img from https://github.com/jayofelony/pwnagotchi```
```wiki : https://github.com/jayofelony/pwnagotchi/wiki```

thanks to jayofelony for the great work

custom faces from there :  https://github.com/sumeshi/PWNAGOTCHI-CUSTOM-FACES-MOD/blob/main/README.md

for use the 3.5 LCD display on the rasp 3b+

Open the "config.txt" file under the boot directory, comment out "dtoverlay=vc4-kms-v3d", and add the following at the end of [all]: 


```[all]```
```dtparam=spi=on```
```dtoverlay=waveshare35a```

```hdmi_force_hotplug=1```
```max_usb_current=1```
```hdmi_group=2```
```hdmi_mode=1```
```hdmi_mode=87```
```hdmi_cvt 480 320 60 6 0 0 0```
```hdmi_drive=2```
```display_rotate=0```

in the config.toml add this :

```ui.display.enabled = true```
```ui.display.type = "waveshare35lcd"```
```ui.display.color = "white"```
```ui.display.fps = 1```
```ui.display.framebuffer = "/dev/fb1"```


on ssh enter this comands :

sudo apt-get install libraspberrypi-dev raspberrypi-kernel-headers

```sudo rm -rf LCD-show```

```git clone https://github.com/goodtft/LCD-show.git```
```chmod -R 755 LCD-show```
```cd LCD-show/```
```sudo ./LCD35-show ```

++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

external wifi ( disable bluetooth also )

sudo nano /boot/firmware/config.txt
uncomment or add under [all] 
```dtoverlay=disable-wifi```

for the Alfa Awus036ACS ( i get from here : https://github.com/lwfinger/rtw88 )

```sudo apt update```
```sudo apt install -y raspberrypi-kernel-headers build-essential git```
```cd /```
```git clone https://github.com/lwfinger/rtw88```
```cd rtw88```
```sudo dkms install $PWD```
```sudo make install_fw```


++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
bluethooth

```bluetoothctl```

Then:

```scan on```
```pair <your-phone-mac>```
```trust <your-phone-mac>```


++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++


and disable the plugin fix_services bec its only for internal
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
