import os
import subprocess
import sys

def check_root():
    """Check if the application is running with root privileges."""
    return os.geteuid() == 0

def get_wireless_interfaces():
    """
    Retrieve a list of wireless interfaces.
    """
    interfaces = []
    try:
        # specific method may vary by distro, but /sys/class/net is standard
        for iface in os.listdir('/sys/class/net'):
            if os.path.exists(f'/sys/class/net/{iface}/wireless'):
                interfaces.append(iface)
            # Fallback check: see if iwconfig lists it
            elif os.path.isdir(f'/sys/class/net/{iface}/phy80211'):
                 interfaces.append(iface)
    except Exception as e:
        print(f"Error listing interfaces via sysfs: {e}")
    
    # Fallback using iwconfig if sysfs fails or returns empty (unlikely on modern linux)
    if not interfaces:
        try:
            result = subprocess.run(['iwconfig'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            for line in result.stdout.split('\n'):
                if 'no wireless extensions' not in line and len(line) > 0 and not line.startswith(' '):
                    interfaces.append(line.split()[0])
        except FileNotFoundError:
            pass # iwconfig might not be installed

    return list(set(interfaces))

def enable_monitor_mode(interface):
    """
    Enable monitor mode on the specified interface.
    Returns (success, new_interface_name, message)
    """
    # Try airmon-ng first as it handles processes conflicting
    try:
        cmd = ['airmon-ng', 'start', interface]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        if result.returncode == 0:
            # Parse output to find monitor interface name (often wlan0mon)
            for line in result.stdout.split('\n'):
                if "monitor mode enabled" in line:
                    # Regex or simple split could work, usually it says "on [interface]"
                    pass
            
            # Simple heuristic: check if interface + 'mon' exists, or if original interface is now monitor
            return True, "Detected via airmon-ng", result.stdout
        else:
            return False, interface, result.stderr
    except FileNotFoundError:
        return False, interface, "airmon-ng not found"

def disable_monitor_mode(interface):
    """
    Disable monitor mode.
    """
    try:
        cmd = ['airmon-ng', 'stop', interface]
        subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except:
        pass

try:
    from manuf import manuf
    # Initialize parser once
    # We check typical locations if the internal one fails, but manuf usually handles it
    mac_parser = manuf.MacParser(update=False)
except ImportError:
    mac_parser = None
    print("Warning: 'manuf' library not found. Vendor lookup disabled.")

def get_vendor(mac):
    """
    Identify vendor from MAC address using manuf library.
    Expected format: AA:BB:CC:DD:EE:FF
    """
    if not mac or not mac_parser:
        return ""
    
    try:
        # get_manuf returns the vendor name or None
        vendor = mac_parser.get_manuf(mac)
        return str(vendor) if vendor else ""
    except:
        return ""

import csv

def parse_airodump_csv(filepath):
    """
    Parses airodump-ng CSV file and returns (networks, clients).
    networks: list of dicts {BSSID, Channel, Privacy, Power, ESSID}
    clients: list of dicts {MAC, Power, BSSID, Probed}
    """
    networks = []
    clients = []
    try:
        # Read raw bytes to handle encoding
        with open(filepath, 'rb') as f:
            raw_content = f.read()
            
        try:
            content = raw_content.decode('utf-8')
        except UnicodeDecodeError:
            try:
                 content = raw_content.decode('gbk')
            except:
                 content = raw_content.decode('latin-1', errors='replace')

        lines = content.splitlines()
            
        # Find station section
        station_index = -1
        for i, line in enumerate(lines):
            if 'Station MAC' in line and 'BSSID' in line: 
                station_index = i
                break
        
        # Parse APs
        ap_lines = lines[:station_index] if station_index != -1 else lines
        if len(ap_lines) > 1:
            reader = csv.reader(ap_lines)
            header_found = False
            for row in reader:
                if not row or len(row) < 13: continue
                if row[0].strip() == 'BSSID':
                    header_found = True
                    continue
                
                if header_found:
                    try:
                        networks.append({
                            "BSSID": row[0].strip(),
                            "Channel": row[3].strip(),
                            "Privacy": row[5].strip(),
                            "Power": row[8].strip(),
                            "ESSID": row[13].strip() or "<Hidden>"
                        })
                    except IndexError:
                        continue

        # Parse Clients
        if station_index != -1 and station_index < len(lines) - 1:
            client_lines = lines[station_index:]
            reader = csv.reader(client_lines)
            header_found = False
            for row in reader:
                if not row or len(row) < 6: continue
                if row[0].strip() == 'Station MAC':
                    header_found = True
                    continue
                    
                if header_found:
                    try:
                        client_mac = row[0].strip()
                        power = row[3].strip()
                        bssid = row[5].strip()
                        probed = ""
                        if len(row) > 6:
                            probed = row[6].strip()
                            
                        clients.append({
                            "MAC": client_mac,
                            "Power": power,
                            "BSSID": bssid,
                            "Probed": probed
                        })
                    except IndexError:
                        continue
                        
        return networks, clients
        
    except Exception:
        return [], []
