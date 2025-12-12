#!/usr/bin/env python3
"""
netzwerkscanner.py

Ein einfacher IP-Scanner mit interaktivem Menü und CLI-Modus.

Deutsch / English:
- Dieses Skript führt Ping-Scans durch, erkennt automatisch das lokale IPv4-Netz (wenn möglich)
  und löst optional Hostnamen auf. Export als CSV/JSON ist möglich.
- This script performs ping scans, auto-detects the local IPv4 network when possible,
  optionally resolves hostnames and can export results as CSV or JSON.

Speichern als: netzwerkscanner.py
"""

from __future__ import annotations
import argparse
import concurrent.futures
import ipaddress
import platform
import re
import socket
import subprocess
import sys
import json
import csv
import os
from typing import Optional, Tuple, List

# ---------- Hilfsfunktion: Kommando ausführen / Helper to run commands ----------

def run_cmd(cmd: List[str]) -> Tuple[int, str]:
    """Führt ein externes Kommando aus und gibt (ExitCode, Stdout) zurück.

    Falls das Kommando nicht gefunden wird, wird (1, "") zurückgegeben.
    Runs an external command and returns (exit_code, stdout).
    If the command is not available, returns (1, "").
    """
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, check=False)
        return p.returncode, p.stdout
    except FileNotFoundError:
        return 1, ""

# ---------- Netzwerkerkennung / Network detection ----------

def detect_network_linux_via_ip() -> Optional[str]:
    """Versucht auf Linux mit `ip route get 1.1.1.1` die Quelladresse zu ermitteln und daraus das Interface-Subnetz.

    Tries to determine the source IP and subnet via `ip` commands.
    """
    code, out = run_cmd(["ip", "route", "get", "1.1.1.1"])
    if code == 0 and out:
        m = re.search(r"src\s+([0-9.]+)", out)
        if m:
            src_ip = m.group(1)
            code2, out2 = run_cmd(["ip", "-o", "-f", "inet", "addr", "show", "to", "match", src_ip])
            if code2 == 0 and out2:
                m2 = re.search(r"inet\s+([0-9./]+)", out2)
                if m2:
                    return m2.group(1)
    # Fallback: alle IPv4-Adressen durchsuchen
    code, out = run_cmd(["ip", "-4", "-o", "addr", "show"])
    if code == 0 and out:
        for line in out.splitlines():
            if " lo " in line:
                continue
            m = re.search(r"inet\s+([0-9./]+)", line)
            if m:
                return m.group(1)
    return None


def detect_network_ifconfig() -> Optional[str]:
    """Ältere Systeme: `ifconfig` auswerten.

    Older systems: parse `ifconfig` output.
    """
    code, out = run_cmd(["ifconfig"])  # older systems
    if code != 0 or not out:
        return None
    # Suche nach "inet" mit optionaler netmask-Angabe
    m = re.search(r"inet\s+(?:addr:)?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)(?:.*?)(?:netmask\s+([0-9.]+)|/([0-9]+))", out, re.S)
    if m:
        ip = m.group(1)
        if m.group(2):
            nm = m.group(2)
            try:
                pref = ipaddress.IPv4Network(f"{ip}/{nm}", strict=False).prefixlen
                return f"{ip}/{pref}"
            except Exception:
                pass
        return f"{ip}/24"
    return None


def detect_network_windows() -> Optional[str]:
    """Windows: ipconfig parsen.

    Parse `ipconfig` on Windows.
    """
    code, out = run_cmd(["ipconfig"])  # Windows
    if code != 0 or not out:
        return None
    ips = re.findall(r"IPv4.*?:\s*([0-9.]+)", out)
    masks = re.findall(r"Subnet Mask.*?:\s*([0-9.]+)", out)
    if ips:
        ip = ips[0]
        mask = masks[0] if masks else "255.255.255.0"
        try:
            pref = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False).prefixlen
            return f"{ip}/{pref}"
        except Exception:
            return f"{ip}/24"
    return None


def detect_network() -> ipaddress.IPv4Network:
    """Hauptfunktion zur Netzwerkerkennung.

    Versucht mehrere Strategien, ansonsten Standard 192.168.1.0/24.
    """
    sys_platform = platform.system().lower()
    candidate = None
    if "linux" in sys_platform or "darwin" in sys_platform:
        candidate = detect_network_linux_via_ip()
        if not candidate:
            candidate = detect_network_ifconfig()
    if not candidate and "windows" in sys_platform:
        candidate = detect_network_windows()
    if not candidate:
        candidate = "192.168.1.0/24"
    if "/" not in candidate:
        candidate = candidate + "/24"
    try:
        net = ipaddress.ip_network(candidate, strict=False)
        return net
    except Exception:
        return ipaddress.ip_network("192.168.1.0/24")

# ---------- Ping-Funktion / Ping function ----------

def ping(ip: ipaddress.IPv4Address, timeout_s: int = 1) -> bool:
    """Pingt eine IPv4-Adresse kurz an.

    Plattformabhängig werden unterschiedliche Argumente an `ping` übergeben.
    Returns True when host replies.
    """
    sys_plat = platform.system().lower()
    if "windows" in sys_plat:
        cmd = ["ping", "-n", "1", "-w", str(int(timeout_s * 1000)), str(ip)]
    else:
        # Bei vielen Unix-Systemen erwartet `-W` ganze Sekunden; wir verwenden mindestens 1s
        cmd = ["ping", "-c", "1", "-W", str(int(max(1, timeout_s))), str(ip)]
    try:
        p = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        return p.returncode == 0
    except Exception:
        return False

# ---------- Hostname-Auflösung / Hostname resolution ----------

def resolve_via_etchosts(ip: str) -> Optional[str]:
    """Prüft /etc/hosts auf einen Eintrag für die IP.

    Check /etc/hosts for an entry for the IP.
    """
    try:
        with open('/etc/hosts', 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = re.split(r'\s+', line)
                if parts[0] == ip and len(parts) >= 2:
                    return parts[1]
    except Exception:
        pass
    return None


def resolve_via_getent(ip: str) -> Optional[str]:
    """Verwendet `getent hosts <ip>` falls verfügbar.

    Use `getent hosts <ip>` when available.
    """
    code, out = run_cmd(["getent", "hosts", ip])
    if code == 0 and out:
        parts = out.split()
        if parts:
            return parts[1]
    return None


def resolve_via_avahi(ip: str) -> Optional[str]:
    """Versucht mDNS via avahi-resolve-address.

    Try mDNS with avahi-resolve-address if available.
    """
    code, out = run_cmd(["avahi-resolve-address", "-n", ip])
    if code == 0 and out:
        parts = out.strip().split()
        if len(parts) >= 2:
            return parts[1]
    return None


def resolve_via_nslookup(ip: str) -> Optional[str]:
    """Versucht eine Reverse-Auflösung via nslookup.

    Try reverse resolution via nslookup.
    """
    code, out = run_cmd(["nslookup", ip])
    if code == 0 and out:
        m = re.search(r"name =\s*([\w.\-]+)\.?", out, re.IGNORECASE)
        if m:
            return m.group(1)
    return None


def resolve_via_nbtscan_windows(ip: str) -> Optional[str]:
    """Windows: versucht nbtstat -A <ip> für NetBIOS-Namen.

    On Windows, try `nbtstat -A <ip>` for NetBIOS names.
    """
    code, out = run_cmd(["nbtstat", "-A", ip])
    if code == 0 and out:
        m = re.search(r"<00>\s+UNIQUE\s+\s+(.+)$", out, re.M)
        if m:
            return m.group(1).strip()
    return None


def resolve_name(ip: str) -> str:
    """Versucht mehrere Auflösungsmethoden und liefert einen Hostnamen oder '-' zurück.

    Tries multiple resolution methods and returns a hostname or '-'.
    """
    try:
        name = socket.gethostbyaddr(ip)[0]
        if name:
            return name
    except Exception:
        pass
    # Weitere Fallbacks
    h = resolve_via_etchosts(ip)
    if h:
        return h
    h = resolve_via_getent(ip)
    if h:
        return h
    h = resolve_via_avahi(ip)
    if h:
        return h
    h = resolve_via_nslookup(ip)
    if h:
        return h
    if platform.system().lower().startswith('win'):
        h = resolve_via_nbtscan_windows(ip)
        if h:
            return h
    return "-"

# ---------- Terminal UI / Menüs ----------

def clear_terminal():
    try:
        if platform.system().lower().startswith('win'):
            os.system('cls')
        else:
            os.system('clear')
    except Exception:
        pass


def start_menu() -> dict:
    """Zeigt das Startmenü an und liest die Wahl ein.

    Displays the start menu and returns the selected option as a dict.
    """
    clear_terminal()
    print('\n=== Netzwerkscanner - Startmenü ===')
    print('1) Scan starten (automatische Erkennung)')
    print('2) Scan mit manuellem Netz (CIDR)')
    print('3) Einstellungen (Worker / Timeout / Hostnamen auflösen)')
    print('4) Beenden')
    choice = input('Wähle: ').strip() or '1'
    return {'choice': choice}


def settings_menu(workers: int, timeout: float, resolve: bool) -> tuple:
    """Einstellungen anzeigen / editieren.

    Show/edit settings.
    """
    print('\n=== Einstellungen ===')
    print(f'1) Worker: {workers}')
    print(f'2) Timeout: {timeout}s')
    print(f'3) Hostnamen auflösen: {"Ja" if resolve else "Nein"}')
    print('4) Zurück')
    c = input('Wähle: ').strip() or '4'
    if c == '1':
        w = input('Neue Worker-Anzahl: ').strip()
        try:
            workers = int(w)
        except Exception:
            print('Ungültig, bleibt unverändert.')
    elif c == '2':
        t = input('Neues Timeout (s): ').strip()
        try:
            timeout = float(t)
        except Exception:
            print('Ungültig, bleibt unverändert.')
    elif c == '3':
        r = input('Hostnamen auflösen? (j/n): ').strip().lower() or 'j'
        resolve = (r == 'j' or r == 'y')
    return workers, timeout, resolve


def export_results(results: List[tuple[str, str]]):
    """Exportiert Ergebnisse als CSV oder JSON (interaktiv).

    Exports results as CSV or JSON (interactive).
    """
    if not results:
        print('Keine Ergebnisse zum Exportieren.')
        return
    print('\nMöchtest du die Ergebnisse exportieren?')
    print('1) CSV')
    print('2) JSON')
    print('3) Nicht exportieren')
    choice = input('Wähle [3]: ').strip() or '3'
    if choice == '3':
        print('Nicht exportiert.')
        return
    filename = input('Dateiname (ohne Endung) [netzscan]: ').strip() or 'netzscan'
    if choice == '1':
        path = filename + '.csv'
        try:
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['ip', 'hostname'])
                for ip, host in results:
                    writer.writerow([ip, host])
            print(f'Ergebnisse als CSV gespeichert: {path}')
        except Exception as e:
            print('Fehler beim Schreiben der CSV:', e)
    elif choice == '2':
        path = filename + '.json'
        try:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump([{'ip': ip, 'hostname': host} for ip, host in results], f, indent=2, ensure_ascii=False)
            print(f'Ergebnisse als JSON gespeichert: {path}')
        except Exception as e:
            print('Fehler beim Schreiben der JSON:', e)

# ---------- Scan-Loop / Scanning ----------

def do_scan(net: ipaddress.IPv4Network, workers: int, timeout: float, resolve: bool) -> List[tuple[str, str]]:
    """Führt den Scan aus und gibt eine Liste (ip, hostname) zurück.

    Performs the scan and returns a list of (ip, hostname).
    """
    print(f"\nScanne Netzwerk: {net} (Hosts: {net.num_addresses - 2 if net.prefixlen < 31 else net.num_addresses})")
    hosts = list(net.hosts())
    if len(hosts) > 1024:
        print('Warnung: Netz > 1024 Hosts — das Scannen kann lange dauern.')

    alive: List[str] = []
    # Ping-Phase: Threads entsprechend `workers`
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(ping, ip, timeout): ip for ip in hosts}
        for fut in concurrent.futures.as_completed(futures):
            ip = futures[fut]
            try:
                ok = fut.result()
            except Exception:
                ok = False
            if ok:
                alive.append(str(ip))

    results: List[tuple[str, str]] = []
    if not resolve:
        for ip in alive:
            results.append((ip, '-'))
    else:
        # Hostname-Auflösung parallel, aber mit Limit, damit das System nicht überlastet wird
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(50, max(5, len(alive)))) as ex:
            futures = {ex.submit(resolve_name, ip): ip for ip in alive}
            for fut in concurrent.futures.as_completed(futures):
                ip = futures[fut]
                try:
                    name = fut.result()
                except Exception:
                    name = '-'
                results.append((ip, name))

    # Sortieren und Ausgabe
    results.sort(key=lambda x: ipaddress.ip_address(x[0]))
    print('\nOnline Geräte:')
    print(f"{'IP':<18} Hostname")
    print('-' * 50)
    for ip, name in results:
        print(f"{ip:<18} {name}")
    print(f"\nFertig. {len(results)} Geräte online.")
    return results


def main_loop():
    workers = 100
    timeout = 1.0
    resolve = True
    while True:
        m = start_menu()
        c = m.get('choice')
        if c == '4':
            print('Beenden.')
            break
        if c == '3':
            workers, timeout, resolve = settings_menu(workers, timeout, resolve)
            continue
        # Wahl 1 oder Default: automatische Erkennung
        if c == '2':
            net_input = input('Netz (CIDR): ').strip()
            try:
                net = ipaddress.ip_network(net_input, strict=False)
            except Exception as e:
                print('Ungültiges Netz:', e)
                continue
        else:
            net = detect_network()
        results = do_scan(net, workers, timeout, resolve)
        export_results(results)
        # Nach Export kehrt die Schleife zum Startmenü zurück


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Netzwerkscanner mit Menü-Schleife')
    parser.add_argument('--no-menu', action='store_true', help='Direkt scannen ohne Menü (nutzt automatische Erkennung)')
    parser.add_argument('--network', '-n', help='Netz im CIDR-Format (nur mit --no-menu sinnvoll)')
    parser.add_argument('--workers', '-w', type=int, default=100, help='Anzahl paralleler Worker')
    parser.add_argument('--timeout', '-t', type=float, default=1.0, help='Ping Timeout in Sekunden')
    parser.add_argument('--no-resolve', action='store_true', help='Keine Hostnamen-Auflösung')
    args = parser.parse_args()

    if args.no_menu:
        # CLI-Mode: direkt scannen und beenden
        workers = args.workers
        timeout = args.timeout
        resolve = not args.no_resolve
        if args.network:
            try:
                net = ipaddress.ip_network(args.network, strict=False)
            except Exception as e:
                print('Ungültiges Netzwerk angegeben:', e)
                sys.exit(1)
        else:
            net = detect_network()
        results = do_scan(net, workers, timeout, resolve)
        export_results(results)
    else:
        main_loop()
