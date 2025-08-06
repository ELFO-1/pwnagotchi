# Standalone WebGPSMap 
Lokale Version des Pwnagotchi webgpsmap Plugins
Zeigt gefundene Access Points mit GPS-Daten auf einer OpenStreetMap-Karte an.
Inklusive Unterstützung für .potfile-Passwörter und Filteroptionen.

Basiert auf dem originalen webgpsmap Plugin von xenDE und dadav
Erweitert und umgeschrieben für standalone Nutzung ohne Pwnagotchi


Was ist neu/anders:

✅ Keine Pwnagotchi-Abhängigkeiten - läuft komplett standalone
✅ Automatische Konfigurationsdatei (webgpsmap_config.json)
✅ Interaktive Verzeichnisabfrage falls das Verzeichnis nicht existiert
✅ Eingebaute HTML-Karte mit OpenStreetMap (kein separates Template nötig)
✅ Moderne Leaflet-Karte mit Popup-Infos und Legende
✅ Offline-Karte Download funktioniert weiterhin
✅ Filter alle , ungecrackt , gecrackt ,
✅ Passwörter im popup

## Installation und start

# 1. Abhängigkeiten installieren
```pip3 install flask python-dateutil```

# 2. Skript ausführbar machen
```chmod +x webgpsmap_standalone.py```

# 3. Starten (verwendet dein Standard-Verzeichnis)
```python3 webgpsmap_standalone.py```

# 4. Oder mit anderem Verzeichnis
```python3 webgpsmap_standalone.py --dir /anderer/pfad/handshakes/```

# 5. Konfiguration interaktiv ändern
```python3 webgpsmap_standalone.py --config``` 


URLs:

    Hauptkarte: http://127.0.0.1:5000
    JSON-API: http://127.0.0.1:5000/all
    Offline-Karte: http://127.0.0.1:5000/offlinemap

Features:

    🔴 Rote Punkte: Ungeknackte APs
    🟢 Grüne Punkte: Geknackte APs (mit Passwort)
    📍 Popup-Info: SSID, MAC, Typ, Genauigkeit, Timestamps
    🔄 Aktualisieren-Button in der Karte
    📥 Offline-Download für komplette HTML-Datei
