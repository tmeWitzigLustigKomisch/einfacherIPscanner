### Kurzbeschreibung
Ein einfacher, robuster IP-/Netzwerk-Scanner, der per Ping aktive Hosts in einem IPv4-Netz erkennt und optional Hostnamen auflöst. Das Tool bietet einen interaktiven Menümodus sowie einen CLI-Modus für Skripting/CI.

### Eigenschaften
- Automatische Netzwerkerkennung (Linux, macOS, Windows)
- Paralleles Scannen via ThreadPoolExecutor
- Optionale Hostnamen-Auflösung (mehrere Strategien: /etc/hosts, getent, avahi, nslookup, nbtscan)
- Export als CSV oder JSON
- Interaktives Terminal-Menü oder Direktlauf über CLI-Optionen
- Keine externen Python-Abhängigkeiten (nur Standardbibliothek)

### Voraussetzungen
- Python 3.8+ (empfohlen)
- Systembefehle: `ping` (plattformabhängig), auf Linux evtl. `ip`, `getent`, `avahi-resolve-address`, `nslookup` (je nach Hostnamen-Auflösung)

Hinweis: Das Skript verwendet die System-Tools `ping` etc.; es benötigt keine Root-Rechte, aber auf manchen Systemen sind ICMP-Operationen beschränkt.

### Installation
Einfach das Repository klonen und das Skript ausführbar machen:

```bash
git clone <repo-url>
cd <repo>
chmod +x netzwerkscanner.py
```

### Verwendung
Interaktiver Modus (Standard):

```bash
./netzwerkscanner.py
```

CLI-Modus (kein Menü, direkt scannen):

```bash
./netzwerkscanner.py --no-menu --network 192.168.1.0/24 --workers 50 --timeout 1.0
```

Optionen (ausführlich):

- `--no-menu` — Direktmodus (kein interaktives Menü)
- `--network, -n` — Netz im CIDR-Format (z. B. `192.168.1.0/24`)
- `--workers, -w` — Anzahl paralleler Threads (Standard: 100)
- `--timeout, -t` — Ping-Timeout in Sekunden (Standard: 1.0)
- `--no-resolve` — Hostnamen nicht auflösen

### Beispiele
Automatisches Netz erkennen und scannen:

```bash
./netzwerkscanner.py --no-menu
```

Scan eines großen Netzes mit angepassten Workern:

```bash
./netzwerkscanner.py --no-menu -n 10.0.0.0/16 -w 200 -t 0.8
```

Export: Nach Beendigung erlaubt das Tool den Export als CSV/JSON.

### Hinweise zur Performance
- Große Netze (>
1024 Hosts) können lange dauern. Die Anzahl paralleler Worker kann angepasst werden, aber zu viele Threads führen ggf. zu hoher Last.
- Hostnamen-Auflösung wird parallel, jedoch mit einer Deckelung (max 50 Worker) ausgeführt, um System-Tools nicht zu überlasten.

### Sicherheit & Lizenz
- Keine Datensammlung oder Telemetrie.
- MIT-Lizenz empfohlen (frei verwendbar). Füge ggf. `LICENSE` mit MIT-Text hinzu.

---

## README.md — English

### Short description
A simple, robust IP/network scanner that discovers live IPv4 hosts by pinging and optionally resolves hostnames. The tool provides an interactive menu and a CLI-mode for scripting/automation.

### Features
- Automatic network detection (Linux, macOS, Windows)
- Parallel scanning using ThreadPoolExecutor
- Optional hostname resolution (multiple strategies: /etc/hosts, getent, avahi, nslookup, nbtscan)
- Export results to CSV or JSON
- Interactive terminal menu or direct CLI invocation
- No external Python dependencies (standard library only)

### Requirements
- Python 3.8+ (recommended)
- System utilities: `ping` (platform-specific), on Linux maybe `ip`, `getent`, `avahi-resolve-address`, `nslookup` depending on hostname resolution used.

Note: The script calls system tools; it doesn't require root but some systems restrict ICMP operations.

### Installation
Clone the repository and make the script executable:

```bash
git clone <repo-url>
cd <repo>
chmod +x netzwerkscanner.py
```

### Usage
Interactive mode (default):

```bash
./netzwerkscanner.py
```

CLI mode (no menu, immediate scan):

```bash
./netzwerkscanner.py --no-menu --network 192.168.1.0/24 --workers 50 --timeout 1.0
```

Options (detailed):

- `--no-menu` — Run directly without interactive menu
- `--network, -n` — Network in CIDR format (e.g. `192.168.1.0/24`)
- `--workers, -w` — Number of parallel threads (default: 100)
- `--timeout, -t` — Ping timeout in seconds (default: 1.0)
- `--no-resolve` — Do not resolve hostnames

### Examples
Automatically detect network and scan:

```bash
./netzwerkscanner.py --no-menu
```

Scan a large network with custom workers:

```bash
./netzwerkscanner.py --no-menu -n 10.0.0.0/16 -w 200 -t 0.8
```

Export: After finishing the scan, the program offers exporting results as CSV/JSON.

### Performance notes
- Scanning large networks (>1024 hosts) can take long. Tune `--workers` for parallelism but be aware of system load.
- Hostname resolution uses up to 50 workers to avoid overwhelming system resolver tools.

### Security & License
- No telemetry or data collection.
- MIT license recommended. Add a `LICENSE` file with the MIT text if desired.


