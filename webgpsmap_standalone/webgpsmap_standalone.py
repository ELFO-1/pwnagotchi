#!/usr/bin/env python3
"""
Standalone WebGPSMap - Lokale Version des Pwnagotchi webgpsmap Plugins
Zeigt gefundene Access Points mit GPS-Daten auf einer OpenStreetMap-Karte an.
Inklusive Unterstützung für .potfile-Passwörter und Filteroptionen.

Basiert auf dem originalen webgpsmap Plugin von xenDE und dadav
Erweitert und umgeschrieben für standalone Nutzung ohne Pwnagotchi
"""

import os
import json
import re
import logging
import datetime
from pathlib import Path
from flask import Flask, Response, request, jsonify
from functools import lru_cache
from dateutil.parser import parse
import argparse
import sys

# Logging Setup
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


class WebGPSMapStandalone:
    def __init__(self, handshakes_dir):
        self.handshakes_dir = handshakes_dir
        self.ALREADY_SENT = list()
        self.SKIP = list()
        self.cracked_passwords = (
            self._load_cracked_passwords()
        )  # Lade Passwörter beim Start

    def normalize_ssid(self, ssid):
        import re

        return re.sub(r"[^a-zA-Z0-9]", "", ssid).lower()

        # Prüfe ob Verzeichnis existiert
        if not os.path.exists(handshakes_dir):
            raise ValueError(
                f"Handshakes-Verzeichnis existiert nicht: {handshakes_dir}"
            )

        logging.info(f"[webgpsmap] Handshakes-Verzeichnis: {handshakes_dir}")
        logging.info(
            f"[webgpsmap] Geladene Passwörter aus Potfiles: {len(self.cracked_passwords)}"
        )

    # cache 2048 items
    @lru_cache(maxsize=2048, typed=False)
    def _get_pos_from_file(self, path):
        return PositionFile(path)

    def _load_cracked_passwords(self):
        """
        Lädt Passwörter aus den verschiedenen .potfile-Dateien.
        Gibt ein Dictionary zurück: { "BSSID_SSID": {"password": "...", "source": "..."} }
        """
        cracked_data = {}
        potfiles = {
            "cracked.pwncrack.potfile": "pwncrack",
            "wpa-sec.cracked.potfile": "wpa-sec",
            "remote_cracking.potfile": "remote_cracking",
        }

        for filename, source_name in potfiles.items():
            filepath = os.path.join(self.handshakes_dir, filename)
            if os.path.exists(filepath):
                logging.info(f"[webgpsmap] Lade Passwörter aus {filename}...")
                try:
                    with open(filepath, "r", errors="ignore") as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue

                            parts = line.split(":")

                            if source_name == "wpa-sec" and len(parts) >= 4:
                                bssid = parts[0].replace(":", "").upper()
                                essid = parts[2]
                                password = parts[3]
                            elif (
                                source_name == "pwncrack"
                                or source_name == "remote_cracking"
                            ) and len(parts) >= 5:
                                bssid = parts[1].replace(":", "").upper()
                                essid = parts[3]
                                password = parts[4]
                            else:
                                logging.debug(
                                    f"Skipping malformed line in {filename}: {line}"
                                )
                                continue

                            key = f"{bssid.lower()}_{self.normalize_ssid(essid)}"
                            if (
                                key not in cracked_data
                            ):  # Nur das erste gefundene Passwort speichern
                                cracked_data[key] = {
                                    "password": password,
                                    "source": source_name,
                                }
                except Exception as e:
                    logging.error(f"[webgpsmap] Fehler beim Laden von {filename}: {e}")
            else:
                logging.debug(f"[webgpsmap] Potfile nicht gefunden: {filename}")
        return cracked_data

    def load_gps_from_dir(self, newest_only=False):
        """
        Parses the gps-data from disk and enriches with cracked passwords.
        """
        handshake_dir = self.handshakes_dir
        gps_data = dict()

        logging.info(f"[webgpsmap] scanning {handshake_dir}")

        all_files = os.listdir(handshake_dir)
        all_pcap_files = [
            os.path.join(handshake_dir, filename)
            for filename in all_files
            if filename.endswith(".pcap")
        ]
        all_geo_or_gps_files = []
        for filename_pcap in all_pcap_files:
            filename_base = filename_pcap[:-5]  # remove ".pcap"
            filename_position = None

            # Prioritize .gps.json, then .geo.json, then .paw-gps.json
            check_order = [".gps.json", ".geo.json", ".paw-gps.json"]
            for ext in check_order:
                check_for = os.path.basename(filename_base) + ext
                if check_for in all_files:
                    filename_position = str(os.path.join(handshake_dir, check_for))
                    break  # Found one, stop searching for this pcap

            if filename_position is not None:
                all_geo_or_gps_files.append(filename_position)
        # DEBUG: Zeige alle Keys aus Potfiles
        # logging.info(f"[DEBUG] Potfile-Keys: {list(self.cracked_passwords.keys())}")

        # DEBUG: Zeige alle Keys aus GPS-Files
        gps_keys = []
        for pos_file in all_geo_or_gps_files:
            try:
                pos = self._get_pos_from_file(pos_file)
                ssid, mac = pos.ssid(), pos.mac()
                if not mac:
                    continue
                gps_key = f"{mac.lower()}_{ssid}"
                gps_keys.append(gps_key)
            except Exception as e:
                continue
        # logging.info(f"[DEBUG] GPS-Keys: {gps_keys}")

        # DEBUG: Zeige gematchte Keys
        # matched = [k for k in gps_keys if k in self.cracked_passwords]
        #  unmatched = [k for k in gps_keys if k not in self.cracked_passwords]
        # logging.info(f"[DEBUG] Gematchte Keys: {matched}")
        # logging.info(f"[DEBUG] Nicht gematchte Keys: {unmatched}")

        if newest_only:
            all_geo_or_gps_files = set(all_geo_or_gps_files) - set(self.ALREADY_SENT)

        logging.info(
            f"[webgpsmap] Found {len(all_geo_or_gps_files)} position-data files from {len(all_pcap_files)} handshakes. Fetching positions ..."
        )

        for pos_file in all_geo_or_gps_files:
            try:
                pos = self._get_pos_from_file(pos_file)
                if (
                    not pos.type() == PositionFile.GPS
                    and not pos.type() == PositionFile.GEO
                    and not pos.type() == PositionFile.PAWGPS
                ):
                    continue

                ssid, mac = pos.ssid(), pos.mac()
                ssid = "unknown" if not ssid else ssid
                if not mac:
                    raise ValueError("Mac can't be parsed from filename")

                pos_type = "unknown"
                if pos.type() == PositionFile.GPS:
                    pos_type = "gps"
                elif pos.type() == PositionFile.GEO:
                    pos_type = "geo"
                elif pos.type() == PositionFile.PAWGPS:
                    pos_type = "paw"

                ap_data = {
                    "ssid": ssid,
                    "mac": mac,
                    "type": pos_type,
                    "lng": pos.lng(),
                    "lat": pos.lat(),
                    "acc": pos.accuracy(),
                    "ts_first": pos.timestamp_first(),
                    "ts_last": pos.timestamp_last(),
                    "pass": None,
                    "pass_source": None,
                }

                # Check for cracked password from potfiles
                cracked_key = f"{mac.lower()}_{self.normalize_ssid(ssid)}"
                if cracked_key in self.cracked_passwords:
                    ap_data["pass"] = self.cracked_passwords[cracked_key]["password"]
                    ap_data["pass_source"] = self.cracked_passwords[cracked_key][
                        "source"
                    ]

                gps_data[ssid + "_" + mac] = ap_data

                self.ALREADY_SENT.append(pos_file)
            except json.JSONDecodeError as error:
                self.SKIP.append(pos_file)
                logging.error(
                    f"[webgpsmap] JSONDecodeError in: {pos_file} - error: {error}"
                )
                continue
            except ValueError as error:
                self.SKIP.append(pos_file)
                logging.error(f"[webgpsmap] ValueError: {pos_file} - error: {error}")
                continue
            except OSError as error:
                self.SKIP.append(pos_file)
                logging.error(f"[webgpsmap] OSError: {pos_file} - error: {error}")
                continue
        logging.info(f"[webgpsmap] loaded {len(gps_data)} positions")
        return gps_data

    def get_html(self):
        """
        Returns the html page with embedded map and filter options
        """
        html_template = (
            """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>WebGPSMap - Standalone</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <style>
        body { margin: 0; padding: 0; font-family: Arial, sans-serif; }
        #map { height: 100vh; width: 100%; }
        .info-panel { 
            position: absolute; 
            top: 10px; 
            right: 10px; 
            background: white; 
            padding: 10px; 
            border-radius: 5px; 
            box-shadow: 0 2px 5px rgba(0,0,0,0.2);
            z-index: 1000;
            max-width: 300px;
        }
        .legend {
            position: absolute;
            bottom: 10px;
            left: 10px;
            background: white;
            padding: 10px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.2);
            z-index: 1000;
        }
        .legend-item {
            display: flex;
            align-items: center;
            margin: 5px 0;
        }
        .legend-color {
            width: 20px;
            height: 20px;
            border-radius: 50%;
            margin-right: 10px;
        }
        .red { background-color: #ff4444; }
        .green { background-color: #44ff44; }

        .filter-panel {
            position: absolute;
            top: 10px;
            left: 10px;
            background: white;
            padding: 10px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.2);
            z-index: 1000;
            max-width: 300px;
        }
        .filter-panel label, .filter-panel select, .filter-panel input {
            display: block;
            margin-bottom: 5px;
            width: 100%;
        }
    </style>
</head>
<body>
    <div id="map"></div>
    <div class="info-panel">
        <h3>WebGPSMap Standalone</h3>
        <p>Handshakes-Verzeichnis:<br><code>"""
            + self.handshakes_dir
            + """</code></p>
        <p id="status">Lade Positionen...</p>
        <button onclick="loadPositions()">Aktualisieren</button>
        <br><br>
        <a href="/offlinemap" download="webgpsmap.html">📥 Offline-Karte herunterladen</a>
    </div>
    <div class="legend">
        <h4>Legende</h4>
        <div class="legend-item">
            <div class="legend-color red"></div>
            <span>Ungeknackt</span>
        </div>
        <div class="legend-item">
            <div class="legend-color green"></div>
            <span>Geknackt (Passwort bekannt)</span>
        </div>
    </div>

    <div class="filter-panel">
        <h4>Filter</h4>
        <label for="statusFilter">Status:</label>
        <select id="statusFilter" onchange="applyFilters()">
            <option value="all">Alle</option>
            <option value="cracked">Geknackt</option>
            <option value="uncracked">Ungeknackt</option>
        </select>

        <label for="ssidSearch">SSID Suche:</label>
        <input type="text" id="ssidSearch" onkeyup="applyFilters()" placeholder="Nach SSID suchen...">

        <label for="sourceFilter">Passwort Quelle:</label>
        <select id="sourceFilter" onchange="applyFilters()">
            <option value="all">Alle</option>
            <option value="pwncrack">pwncrack</option>
            <option value="wpa-sec">wpa-sec</option>
            <option value="remote_cracking">remote_cracking</option>
            <option value="none">Keine (Ungeknackt)</option>
        </select>
    </div>

    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <script>
        var map = L.map('map').setView([48.2685195, 10.0766273], 13);
        var allPositions = []; // Store all loaded positions
        var markers = [];

        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '© OpenStreetMap contributors'
        }).addTo(map);

        function loadPositions() {
            document.getElementById('status').innerHTML = 'Lade Positionen...';
            fetch('/all')
                .then(response => response.json())
                .then(data => {
                    allPositions = Object.values(data); // Convert object to array
                    positionsLoaded = true;
                    applyFilters(); // Apply filters after loading
                })
                .catch(error => {
                    console.error('Error:', error);
                    document.getElementById('status').innerHTML = 'Fehler beim Laden!';
                });
        }

        function applyFilters() {
            // Clear existing markers
            markers.forEach(marker => map.removeLayer(marker));
            markers = [];

            var statusFilter = document.getElementById('statusFilter').value;
            var ssidSearch = document.getElementById('ssidSearch').value.toLowerCase();
            var sourceFilter = document.getElementById('sourceFilter').value;

            var filteredPositions = allPositions.filter(pos => {
                // Status Filter
                if (statusFilter === 'cracked' && !pos.pass) return false;
                if (statusFilter === 'uncracked' && pos.pass) return false;

                // SSID Search
                if (ssidSearch && !pos.ssid.toLowerCase().includes(ssidSearch)) return false;

                // Source Filter
                if (sourceFilter !== 'all') {
                    if (sourceFilter === 'none' && pos.pass) return false; // If 'none' selected, hide cracked
                    if (sourceFilter !== 'none' && pos.pass_source !== sourceFilter) return false; // If specific source, match it
                }

                return true;
            });

            var count = 0;
            var crackedCount = 0;

            filteredPositions.forEach(pos => {
                count++;

                var color = pos.pass ? 'green' : 'red';
                if (pos.pass) crackedCount++;

                var marker = L.circleMarker([pos.lat, pos.lng], {
                    color: color,
                    fillColor: color,
                    fillOpacity: 0.7,
                    radius: 8
                }).addTo(map);

                var popupContent = '<b>' + pos.ssid + '</b><br>' +
                                 'MAC: ' + pos.mac + '<br>' +
                                 'Typ: ' + pos.type + '<br>' +
                                 'Genauigkeit: ' + (pos.acc ? pos.acc.toFixed(2) : 'N/A') + 'm<br>' +
                                 'Zuerst gesehen: ' + new Date(pos.ts_first * 1000).toLocaleString() + '<br>' +
                                 'Zuletzt gesehen: ' + new Date(pos.ts_last * 1000).toLocaleString();

                if (pos.pass) {
                    popupContent += '<br><b>Passwort: ' + pos.pass + '</b>';
                    popupContent += '<br>Quelle: ' + pos.pass_source;
                }

                marker.bindPopup(popupContent);
                markers.push(marker);
            });

            document.getElementById('status').innerHTML = 
                count + ' Access Points angezeigt<br>' +
                crackedCount + ' davon geknackt';

            // Fit map to show all markers
            if (markers.length > 0) {
                var group = new L.featureGroup(markers);
                map.fitBounds(group.getBounds().pad(0.1));
            } else {
                // If no markers, reset view to default or last known good view
                map.setView([48.2685195, 10.0766273], 13);
            }
        }

        // Load positions on page load
        loadPositions();
    </script>
</body>
</html>"""
        )
        return html_template


class PositionFile:
    """
    Wraps gps / net-pos files
    """

    GPS = 1
    GEO = 2
    PAWGPS = 3

    def __init__(self, path):
        self._file = path
        self._filename = os.path.basename(path)
        try:
            logging.debug(f"[webgpsmap] loading {path}")
            with open(path, "r") as json_file:
                self._json = json.load(json_file)
            logging.debug(f"[webgpsmap] loaded {path}")
        except json.JSONDecodeError as js_e:
            raise js_e

    def mac(self):
        """
        Returns the mac from filename
        """
        parsed_mac = re.search(
            r".*_?([a-zA-Z0-9]{12})\.(?:gps|geo|paw-gps)\.json", self._filename
        )
        if parsed_mac:
            mac = parsed_mac.groups()[0]
            return mac
        return None

    def ssid(self):
        """
        Returns the ssid from filename
        """
        parsed_ssid = re.search(
            r"(.+)_[a-zA-Z0-9]{12}\.(?:gps|geo|paw-gps)\.json", self._filename
        )
        if parsed_ssid:
            return parsed_ssid.groups()[0]
        return None

    def json(self):
        """
        returns the parsed json
        """
        return self._json

    def timestamp_first(self):
        """
        returns the timestamp of AP first seen
        """
        # use file timestamp creation time of the pcap file
        return int("%.0f" % os.path.getctime(self._file))

    def timestamp_last(self):
        """
        returns the timestamp of AP last seen
        """
        return_ts = None
        if "ts" in self._json:
            return_ts = self._json["ts"]
        elif "Updated" in self._json:
            # convert gps datetime to unix timestamp: "2019-10-05T23:12:40.422996+01:00"
            dateObj = parse(self._json["Updated"])
            return_ts = int("%.0f" % dateObj.timestamp())
        else:
            # use file timestamp last modification of the json file
            return_ts = int("%.0f" % os.path.getmtime(self._file))
        return return_ts

    def password(self):
        """
        returns the password from file.pcap.cracked or None
        (This function is mostly for legacy .pcap.cracked files,
         passwords are now primarily loaded from .potfiles)
        """
        return_pass = None
        # This part is less relevant now as potfiles are preferred
        # but kept for completeness if .pcap.cracked files are still used.
        base_filename = self._file.rsplit(".", 2)[
            0
        ]  # Remove .gps.json or .geo.json or .paw-gps.json
        password_file_path = base_filename + ".pcap.cracked"
        if os.path.isfile(password_file_path):
            try:
                with open(password_file_path, "r") as password_file:
                    return_pass = password_file.read().strip()
            except OSError as error:
                logging.error(
                    f"[webgpsmap] OS error loading password: {password_file_path} - error: {format(error)}"
                )
            except Exception as e:
                logging.error(
                    f"[webgpsmap] Unexpected error loading password: {password_file_path} - error: {e}"
                )
        return return_pass

    def type(self):
        """
        returns the type of the file
        """
        if self._file.endswith(".gps.json"):
            return PositionFile.GPS
        if self._file.endswith(".geo.json"):
            return PositionFile.GEO
        if self._file.endswith(".paw-gps.json"):
            return PositionFile.PAWGPS
        return None

    def lat(self):
        try:
            lat = None
            # try to get value from known formats
            if "Latitude" in self._json:
                lat = self._json["Latitude"]
            if "lat" in self._json:
                lat = self._json[
                    "lat"
                ]  # an old paw-gps format: {"long": 14.693561, "lat": 40.806375}
            if "location" in self._json:
                if "lat" in self._json["location"]:
                    lat = self._json["location"]["lat"]
            # check value
            if lat is None:
                raise ValueError(f"Lat is None in {self._filename}")
            if lat == 0:
                raise ValueError(f"Lat is 0 in {self._filename}")
            return lat
        except KeyError:
            pass
        return None

    def lng(self):
        try:
            lng = None
            # try to get value from known formats
            if "Longitude" in self._json:
                lng = self._json["Longitude"]
            if "long" in self._json:
                lng = self._json[
                    "long"
                ]  # an old paw-gps format: {"long": 14.693561, "lat": 40.806375}
            if "location" in self._json:
                if "lng" in self._json["location"]:
                    lng = self._json["location"]["lng"]
            # check value
            if lng is None:
                raise ValueError(f"Lng is None in {self._filename}")
            if lng == 0:
                raise ValueError(f"Lng is 0 in {self._filename}")
            return lng
        except KeyError:
            pass
        return None

    def accuracy(self):
        if self.type() == PositionFile.GPS:
            return 50.0  # a default
        if self.type() == PositionFile.PAWGPS:
            return 50.0  # a default
        if self.type() == PositionFile.GEO:
            try:
                return self._json["accuracy"]
            except KeyError:
                pass
        return None


def load_config():
    """Lädt die Konfiguration aus config.json oder erstellt eine neue"""
    config_file = "webgpsmap_config.json"
    default_config = {
        "handshakes_dir": "/home/myscripts/pwnagotchi/handshakes/",
        "host": "127.0.0.1",
        "port": 5000,
        "debug": False,
    }

    if os.path.exists(config_file):
        try:
            with open(config_file, "r") as f:
                config = json.load(f)
            logging.info(f"Konfiguration geladen aus {config_file}")
            return config
        except Exception as e:
            logging.error(f"Fehler beim Laden der Konfiguration: {e}")
            logging.info("Verwende Standard-Konfiguration")
            return default_config
    else:
        # Erstelle neue Konfigurationsdatei
        with open(config_file, "w") as f:
            json.dump(default_config, f, indent=4)
        logging.info(f"Neue Konfigurationsdatei erstellt: {config_file}")
        return default_config


def save_config(config):
    """Speichert die Konfiguration"""
    config_file = "webgpsmap_config.json"
    try:
        with open(config_file, "w") as f:
            json.dump(config, f, indent=4)
        logging.info(f"Konfiguration gespeichert in {config_file}")
    except Exception as e:
        logging.error(f"Fehler beim Speichern der Konfiguration: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="WebGPSMap Standalone - Zeigt Access Points auf einer Karte an"
    )
    parser.add_argument("--dir", "-d", help="Handshakes-Verzeichnis")
    parser.add_argument(
        "--host", default="127.0.0.1", help="Host-Adresse (Standard: 127.0.0.1)"
    )
    parser.add_argument(
        "--port", "-p", type=int, default=5000, help="Port (Standard: 5000)"
    )
    parser.add_argument("--debug", action="store_true", help="Debug-Modus aktivieren")
    parser.add_argument(
        "--config", action="store_true", help="Konfiguration interaktiv ändern"
    )

    args = parser.parse_args()

    # Lade Konfiguration
    config = load_config()

    # Interaktive Konfiguration
    if args.config:
        print("\n=== WebGPSMap Konfiguration ===")
        print(f"Aktuelles Handshakes-Verzeichnis: {config['handshakes_dir']}")
        new_dir = input("Neues Verzeichnis (Enter für keine Änderung): ").strip()
        if new_dir:
            config["handshakes_dir"] = new_dir

        print(f"Aktuelle Host-Adresse: {config['host']}")
        new_host = input("Neue Host-Adresse (Enter für keine Änderung): ").strip()
        if new_host:
            config["host"] = new_host

        print(f"Aktueller Port: {config['port']}")
        new_port = input("Neuer Port (Enter für keine Änderung): ").strip()
        if new_port:
            try:
                config["port"] = int(new_port)
            except ValueError:
                print("Ungültiger Port, verwende aktuellen Wert")

        save_config(config)
        print("Konfiguration gespeichert!")
        return

    # Command-line Argumente überschreiben Konfiguration
    if args.dir:
        config["handshakes_dir"] = args.dir
    if args.host != "127.0.0.1":
        config["host"] = args.host
    if args.port != 5000:
        config["port"] = args.port
    if args.debug:
        config["debug"] = True
        logging.getLogger().setLevel(logging.DEBUG)

    # Verzeichnis prüfen/abfragen
    handshakes_dir = config["handshakes_dir"]

    if not os.path.exists(handshakes_dir):
        print(f"\n❌ Handshakes-Verzeichnis existiert nicht: {handshakes_dir}")
        print("\nBitte gib ein gültiges Verzeichnis an:")
        while True:
            new_dir = input("Handshakes-Verzeichnis: ").strip()
            if os.path.exists(new_dir):
                handshakes_dir = new_dir
                config["handshakes_dir"] = handshakes_dir
                save_config(config)
                break
            else:
                print(f"❌ Verzeichnis existiert nicht: {new_dir}")

    print(f"\n🗂️  Handshakes-Verzeichnis: {handshakes_dir}")

    # Erstelle WebGPSMap Instanz
    try:
        webgps = WebGPSMapStandalone(handshakes_dir)
    except ValueError as e:
        print(f"❌ Fehler: {e}")
        sys.exit(1)

    # Flask App erstellen
    app = Flask(__name__)

    @app.route("/")
    def index():
        webgps.ALREADY_SENT = list()  # Reset for fresh load
        return Response(webgps.get_html(), mimetype="text/html")

    @app.route("/all")
    def get_all_positions():
        webgps.ALREADY_SENT = list()  # Reset for fresh load
        data = webgps.load_gps_from_dir()
        return jsonify(data)

    @app.route("/offlinemap")
    def get_offline_map():
        webgps.ALREADY_SENT = list()  # Reset for fresh load
        json_data = json.dumps(webgps.load_gps_from_dir())
        html_data = webgps.get_html()
        html_data = html_data.replace(
            "var allPositions = [];",
            "var allPositions = Object.values("
            + json_data
            + ");positionsLoaded=true;applyFilters();",
        )
        response = Response(html_data, mimetype="text/html")
        response.headers["Content-Disposition"] = "attachment; filename=webgpsmap.html"
        return response

    # Server starten
    print(f"\n🚀 Starte WebGPSMap Server...")
    print(f"🌐 URL: http://{config['host']}:{config['port']}")
    print(f"📱 Offline-Karte: http://{config['host']}:{config['port']}/offlinemap")
    print(f"⚙️  Konfiguration ändern: python3 {sys.argv[0]} --config")
    print(f"\n🛑 Server stoppen: Strg+C")

    try:
        app.run(host=config["host"], port=config["port"], debug=config["debug"])
    except KeyboardInterrupt:
        print("\n\n👋 Server gestoppt!")
    except Exception as e:
        print(f"\n❌ Fehler beim Starten des Servers: {e}")


if __name__ == "__main__":
    main()
