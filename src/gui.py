from PyQt6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QLabel, QComboBox, QPushButton, QTableWidget, 
                             QTableWidgetItem, QHeaderView, QMessageBox, QMenu,
                             QDialog, QFormLayout, QSpinBox, QDialogButtonBox,
                             QApplication, QSplitter, QListWidget, QInputDialog)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QAction, QColor, QBrush
from .utils import get_wireless_interfaces, enable_monitor_mode, disable_monitor_mode, check_root, get_vendor
from .process import AirodumpScanner, Mdk4Attacker, HunterThread

class AttackConfigDialog(QDialog):
    def __init__(self, parent, essid, bssid, channel):
        super().__init__(parent)
        self.setWindowTitle("Configure Attack")
        self.resize(300, 200)
        
        layout = QVBoxLayout(self)
        form = QFormLayout()
        
        self.lbl_essid = QLabel(essid)
        self.lbl_bssid = QLabel(bssid)
        self.lbl_channel = QLabel(channel)
        
        # Speed configuration
        self.spin_speed = QSpinBox()
        self.spin_speed.setRange(0, 10000)
        self.spin_speed.setValue(2000) # Default from user request
        self.spin_speed.setSingleStep(100)
        self.spin_speed.setSuffix(" pps")
        self.spin_speed.setToolTip("Packets per second. 0 = Unlimited.")
        
        form.addRow("Target SSID:", self.lbl_essid)
        form.addRow("Target BSSID:", self.lbl_bssid)
        form.addRow("Channel:", self.lbl_channel)
        form.addRow("Packet Speed (-s):", self.spin_speed)
        
        layout.addLayout(form)
        
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        
    def get_speed(self):
        return self.spin_speed.value()

class HunterDialog(QDialog):
    def __init__(self, parent, current_targets=[]):
        super().__init__(parent)
        self.setWindowTitle("Hunter Mode Configuration")
        self.resize(400, 300)
        
        layout = QVBoxLayout(self)
        
        layout.addWidget(QLabel("<b>Target ESSIDs (Prey List)</b>"))
        layout.addWidget(QLabel("Hunter will periodically scan for these networks and attack them automatically."))
        
        self.list_targets = QListWidget()
        self.list_targets.addItems(current_targets)
        layout.addWidget(self.list_targets)
        
        btn_layout = QHBoxLayout()
        self.btn_add = QPushButton("Add ESSID")
        self.btn_add.clicked.connect(self.add_target)
        self.btn_remove = QPushButton("Remove Selected")
        self.btn_remove.clicked.connect(self.remove_target)
        btn_layout.addWidget(self.btn_add)
        btn_layout.addWidget(self.btn_remove)
        layout.addLayout(btn_layout)
        
        # Speed config
        form = QFormLayout()
        self.spin_speed = QSpinBox()
        self.spin_speed.setRange(0, 10000)
        self.spin_speed.setValue(2000)
        self.spin_speed.setSuffix(" pps")
        form.addRow("Attack Speed:", self.spin_speed)
        
        self.spin_scan_duration = QSpinBox()
        self.spin_scan_duration.setRange(5, 120)
        self.spin_scan_duration.setValue(15)
        self.spin_scan_duration.setSuffix(" s")
        form.addRow("Scan Interval:", self.spin_scan_duration)
        
        layout.addLayout(form)
        
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        
    def add_target(self):
        from PyQt6.QtWidgets import QInputDialog
        text, ok = QInputDialog.getText(self, "Add Target", "Enter ESSID:")
        if ok and text:
            self.list_targets.addItem(text)
            
    def remove_target(self):
        for item in self.list_targets.selectedItems():
            self.list_targets.takeItem(self.list_targets.row(item))
            
    def get_targets(self):
        targets = []
        for i in range(self.list_targets.count()):
            targets.append(self.list_targets.item(i).text())
        return targets
        
    def get_speed(self):
        return self.spin_speed.value()

    def get_scan_duration(self):
        return self.spin_scan_duration.value()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WiFi Auditor - Python GUI")
        self.resize(900, 600)
        
        # State
        self.current_interface = None
        self.scanner = None
        self.attacker = None
        self.hunter = None
        self.hunter_targets = [] # Persist targets in memory
        self.is_root = check_root()
        self.monitor_interface = None
        
        # UI Setup
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Top Bar: Interface Selection
        top_layout = QHBoxLayout()
        
        top_layout.addWidget(QLabel("Interface:"))
        self.combo_interfaces = QComboBox()
        top_layout.addWidget(self.combo_interfaces)
        
        self.btn_refresh = QPushButton("Refresh")
        self.btn_refresh.clicked.connect(self.refresh_interfaces)
        top_layout.addWidget(self.btn_refresh)
        
        self.btn_monitor = QPushButton("Enable Monitor Mode")
        self.btn_monitor.clicked.connect(self.toggle_monitor_mode)
        top_layout.addWidget(self.btn_monitor)
        
        layout.addLayout(top_layout)
        
        # Scan Controls
        scan_layout = QHBoxLayout()
        self.btn_scan = QPushButton("Start Scan")
        self.btn_scan.clicked.connect(self.toggle_scan)
        self.btn_scan.setEnabled(False) # Disabled until interface selected/monitor mode
        scan_layout.addWidget(self.btn_scan)
        
        self.btn_stop_attack = QPushButton("Stop Active Attack")
        self.btn_stop_attack.clicked.connect(self.stop_attack)
        self.btn_stop_attack.setEnabled(False)
        self.btn_stop_attack.setStyleSheet("background-color: #ffcccc; color: red;") # Visual warning
        scan_layout.addWidget(self.btn_stop_attack)
        
        # Hunter Button (Moved here)
        self.btn_hunter = QPushButton("Hunter Mode")
        self.btn_hunter.clicked.connect(self.toggle_hunter)
        self.btn_hunter.setStyleSheet("background-color: #333; color: white; font-weight: bold;")
        scan_layout.addWidget(self.btn_hunter)
        
        # Attack Stats Label
        self.lbl_attack_stats = QLabel("")
        self.lbl_attack_stats.setStyleSheet("font-weight: bold; color: darkred;")
        scan_layout.addWidget(self.lbl_attack_stats)
        
        layout.addLayout(scan_layout)
        
        # --- Main Content Splitter ---
        splitter = QSplitter(Qt.Orientation.Vertical)
        layout.addWidget(splitter)
        
        # === Top: AP Table ===
        ap_widget = QWidget()
        ap_layout = QVBoxLayout(ap_widget)
        ap_layout.setContentsMargins(0, 0, 0, 0)
        
        ap_layout.addWidget(QLabel("<b>Access Points (WiFi Networks)</b>"))
        self.table = QTableWidget()
        self.table.setColumnCount(6) # Added Vendor
        self.table.setHorizontalHeaderLabels(["ESSID", "BSSID", "Vendor", "Channel", "Power", "Privacy"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        
        # Set default column widths
        self.table.setColumnWidth(0, 180) # ESSID
        self.table.setColumnWidth(1, 140) # BSSID
        self.table.setColumnWidth(2, 100) # Vendor (New)
        self.table.setColumnWidth(3, 60)  # Channel
        self.table.setColumnWidth(4, 60)  # Power
        
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        self.table.itemSelectionChanged.connect(self.update_client_view)
        ap_layout.addWidget(self.table)
        
        splitter.addWidget(ap_widget)
        
        # === Bottom: Clients Table ===
        client_widget = QWidget()
        client_layout = QVBoxLayout(client_widget)
        client_layout.setContentsMargins(0, 0, 0, 0)
        
        client_layout.addWidget(QLabel("<b>Connected Clients (Devices)</b> - Select an AP above to filter"))
        self.clients_table = QTableWidget()
        self.clients_table.setColumnCount(5) # Added Vendor
        self.clients_table.setHorizontalHeaderLabels(["Station MAC", "Vendor", "Power", "BSSID", "Probed ESSIDs"])
        self.clients_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.clients_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.clients_table.setAlternatingRowColors(True)
        client_layout.addWidget(self.clients_table)
        
        splitter.addWidget(client_widget)
        
        # Set initial sizes for splitter (60% top, 40% bottom)
        splitter.setSizes([400, 200])
        
        # Data Storage
        self.all_clients = [] # Store latest clients data
        
        # Status Bar
        self.status_label = QLabel("Ready")
        self.statusBar().addWidget(self.status_label)
        
        # Initial Refresh
        self.refresh_interfaces()
        
        # Check root on startup
        if not check_root():
            QMessageBox.warning(self, "Permission Error", "This application requires root privileges to function correctly.\nPlease run with sudo.")

    def refresh_interfaces(self):
        self.combo_interfaces.clear()
        interfaces = get_wireless_interfaces()
        self.combo_interfaces.addItems(interfaces)
        if interfaces:
            self.btn_scan.setEnabled(self.is_root)
        else:
            self.btn_scan.setEnabled(False)
        self.btn_monitor.setEnabled(self.is_root)
        self.btn_hunter.setEnabled(self.is_root)

    def toggle_monitor_mode(self):
        iface = self.combo_interfaces.currentText()
        if not iface:
            return

        self.status_label.setText(f"Enabling monitor mode on {iface}...")
        # Note: This is blocking, ideally runs in thread but for simplicity/sudo speed we run it here
        success, msg, output = enable_monitor_mode(iface)
        
        if success:
            self.monitor_interface = msg
            self.refresh_interfaces()
            index = self.combo_interfaces.findText(msg)
            if index >= 0:
                self.combo_interfaces.setCurrentIndex(index)
            self.status_label.setText(f"Monitor mode enabled on {msg}")
            QMessageBox.information(self, "Success", f"Monitor mode enabled on {msg}.")
        else:
            self.status_label.setText("Failed to enable monitor mode")
            QMessageBox.critical(self, "Error", f"Failed to enable monitor mode.\n{output}")

    def toggle_hunter(self):
        if self.hunter and self.hunter.isRunning():
            self.hunter.stop()
            self.hunter.wait()
            self.btn_hunter.setText("Hunter Mode")
            self.btn_hunter.setStyleSheet("background-color: #333; color: white; font-weight: bold;")
            self.refresh_interfaces()
            self.status_label.setText("Hunter Mode Stopped")
            return

        iface = self.combo_interfaces.currentText()
        if not iface:
            return
            
        # Show Config
        dialog = HunterDialog(self, self.hunter_targets)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.hunter_targets = dialog.get_targets()
            speed = dialog.get_speed()
            scan_duration = dialog.get_scan_duration()
            
            if not self.hunter_targets:
                QMessageBox.warning(self, "Error", "No targets specified!")
                return
                
            # Stop everything else
            if self.scanner: self.scanner.stop(); self.scanner.wait()
            if self.attacker: self.attacker.stop(); self.attacker.wait()
            self.btn_scan.setText("Start Scan")
            self.btn_scan.setEnabled(False)
            self.btn_stop_attack.setEnabled(False)
            
            # Start Hunter
            self.hunter = HunterThread(iface, self.hunter_targets, speed, scan_duration)
            self.hunter.status_update.connect(self.status_label.setText)
            self.hunter.stats_update.connect(self.lbl_attack_stats.setText)
            self.hunter.start()
            
            self.btn_hunter.setText("Stop Hunter")
            self.btn_hunter.setStyleSheet("background-color: darkred; color: white; font-weight: bold;")
            QMessageBox.information(self, "Hunter Active", "Hunter Mode is running.\nIt will periodically scan for targets and attack them.")

    def toggle_scan(self):
        if self.scanner and self.scanner.isRunning():
            self.scanner.stop()
            self.btn_scan.setText("Start Scan")
            self.status_label.setText("Scan stopped")
        else:
            iface = self.combo_interfaces.currentText()
            if not iface:
                return
                
            self.scanner = AirodumpScanner(iface)
            self.scanner.networks_found.connect(self.update_table)
            self.scanner.start()
            self.btn_scan.setText("Stop Scan")
            self.status_label.setText(f"Scanning on {iface}...")

    def update_table(self, networks, clients):
        # Store clients for filtering
        self.all_clients = clients
        
        # Update Status Bar
        if self.scanner and self.scanner.isRunning():
            self.status_label.setText(f"Scanning... Found {len(networks)} networks, {len(clients)} clients.")

        # --- Update AP Table (Existing Logic) ---
        # Map existing rows by BSSID
        existing_rows = {}
        for row in range(self.table.rowCount()):
            bssid_item = self.table.item(row, 1)
            if bssid_item:
                existing_rows[bssid_item.text()] = row
        
        self.table.setSortingEnabled(False) # Disable sorting while updating
        
        for net in networks:
            bssid = net['BSSID']
            essid = net['ESSID']
            channel = net['Channel']
            power = net['Power'] # Usually a negative string like "-55"
            privacy = net['Privacy']
            vendor = get_vendor(bssid)
            
            # Determine color based on power (Reverted to High Saturation)
            try:
                p_val = int(power)
                if p_val >= -60:
                    color = QColor("#90EE90") # Light Green
                elif p_val >= -80:
                    color = QColor("#FFD700") # Gold
                else:
                    color = QColor("#FF6347") # Tomato
            except:
                color = QColor("white")

            # Text color should be black for readability on these colors
            text_brush = QBrush(QColor("black"))

            if bssid in existing_rows:
                row = existing_rows[bssid]
                # Update text
                self.table.item(row, 0).setText(essid)
                self.table.item(row, 2).setText(vendor)
                self.table.item(row, 3).setText(channel)
                self.table.item(row, 4).setText(power)
                self.table.item(row, 5).setText(privacy)
                
                # Update color for all columns in this row
                for col in range(6):
                    item = self.table.item(row, col)
                    if item: 
                        item.setBackground(color)
                        item.setForeground(text_brush)
            else:
                row = self.table.rowCount()
                self.table.insertRow(row)
                
                # Create items with color
                items = [
                    QTableWidgetItem(essid),
                    QTableWidgetItem(bssid),
                    QTableWidgetItem(vendor),
                    QTableWidgetItem(channel),
                    QTableWidgetItem(power),
                    QTableWidgetItem(privacy)
                ]
                
                for col, item in enumerate(items):
                    item.setBackground(color)
                    item.setForeground(text_brush)
                    self.table.setItem(row, col, item)
                
        self.table.setSortingEnabled(True)
        
        # Refresh client view in case data changed
        self.update_client_view()

    def update_client_view(self):
        # Get selected AP BSSID
        selected_bssid = None
        current_row = self.table.currentRow()
        if current_row >= 0:
            selected_bssid = self.table.item(current_row, 1).text()
            
        self.clients_table.setSortingEnabled(False)
        self.clients_table.setRowCount(0) # Clear current list
        
        text_brush = QBrush(QColor("black"))
        
        for client in self.all_clients:
            # If AP selected, filter. If not, show all? Or show none? 
            # Showing all might be messy. Let's show only if matches or if client not associated (BSSID contains 'not associated')
            # Standard behavior: Show clients for selected AP.
            
            if selected_bssid:
                if client['BSSID'] != selected_bssid:
                    continue
            else:
                # If nothing selected, maybe show unassociated clients or nothing?
                # Let's show nothing to keep it clean, or maybe all? 
                # "Select an AP above to filter" suggests we should filter.
                # But showing all lets users see rogue devices.
                # Let's show all if nothing selected.
                pass

            row = self.clients_table.rowCount()
            self.clients_table.insertRow(row)
            
            power = client['Power']
            vendor = get_vendor(client['MAC'])
            
            try:
                p_val = int(power)
                if p_val >= -60:
                    color = QColor("#90EE90") 
                elif p_val >= -80:
                    color = QColor("#FFD700")
                else:
                    color = QColor("#FF6347")
            except:
                color = QColor("white")
            
            items = [
                QTableWidgetItem(client['MAC']),
                QTableWidgetItem(vendor),
                QTableWidgetItem(power),
                QTableWidgetItem(client['BSSID']),
                QTableWidgetItem(client['Probed'])
            ]
            
            for col, item in enumerate(items):
                item.setBackground(color)
                item.setForeground(text_brush)
                self.clients_table.setItem(row, col, item)
                
        self.clients_table.setSortingEnabled(True)

    def show_context_menu(self, position):
        menu = QMenu()
        
        # Attack Actions
        deauth_action = QAction("Deauth Attack (mdk4)", self)
        deauth_action.triggered.connect(self.start_deauth)
        menu.addAction(deauth_action)
        
        menu.addSeparator()
        
        # Copy Actions
        copy_essid = QAction("Copy ESSID", self)
        copy_essid.triggered.connect(lambda: self.copy_to_clipboard(0))
        menu.addAction(copy_essid)
        
        copy_bssid = QAction("Copy BSSID", self)
        copy_bssid.triggered.connect(lambda: self.copy_to_clipboard(1))
        menu.addAction(copy_bssid)
        
        menu.exec(self.table.viewport().mapToGlobal(position))

    def copy_to_clipboard(self, col_index):
        row = self.table.currentRow()
        if row >= 0:
            text = self.table.item(row, col_index).text()
            QApplication.clipboard().setText(text)
            self.status_label.setText(f"Copied: {text}")

    def start_deauth(self):
        # Get all selected rows
        selected_rows = set()
        for item in self.table.selectedItems():
            selected_rows.add(item.row())
            
        if not selected_rows:
            return
            
        selected_rows = sorted(list(selected_rows))
        
        # Collect Data
        targets = [] # List of (essid, bssid, channel)
        channels = set()
        
        for row in selected_rows:
            essid = self.table.item(row, 0).text()
            bssid = self.table.item(row, 1).text()
            channel = self.table.item(row, 3).text() # Vendor is at 2 now
            
            targets.append((essid, bssid, channel))
            channels.add(channel)
            
        iface = self.combo_interfaces.currentText()
        
        # Prepare Dialog info
        if len(targets) == 1:
            target_essid = targets[0][0]
            target_bssid = targets[0][1]
            target_channel = targets[0][2]
        else:
            target_essid = f"{len(targets)} Selected Targets"
            target_bssid = "Multiple BSSIDs"
            target_channel = ",".join(sorted(list(channels)))

        # Show config dialog
        dialog = AttackConfigDialog(self, target_essid, target_bssid, target_channel)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            # STOP SCANNING
            if self.scanner and self.scanner.isRunning():
                self.scanner.stop()
                self.scanner.wait()
                self.btn_scan.setText("Start Scan")
                self.status_label.setText("Scan paused for attack")
            
            speed = dialog.get_speed()
            
            if self.attacker and self.attacker.isRunning():
                self.attacker.stop()
                self.attacker.wait()
            
            # Determine Attack Mode (Single vs Multi)
            final_targets = []
            if len(targets) == 1:
                final_targets.append((targets[0][1], targets[0][2])) # bssid, channel
            else:
                # targets is list of (essid, bssid, channel)
                for t in targets:
                    final_targets.append((t[1], t[2]))

            self.attacker = Mdk4Attacker(iface, final_targets, speed=speed)
            self.attacker.finished.connect(self.on_attack_finished)
            self.attacker.stats_update.connect(self.lbl_attack_stats.setText) 
            self.attacker.start()
            
            self.status_label.setText(f"Attacking {target_essid} at {speed} pps...")
            self.btn_stop_attack.setEnabled(True)
            self.lbl_attack_stats.setText("Initializing attack...")
            
            QMessageBox.information(self, "Attack Started", f"Attack started on {target_essid}.\nSpeed: {speed} pps\nScanner paused.")

    def stop_attack(self):
        if self.attacker and self.attacker.isRunning():
            self.attacker.stop()
            self.attacker.wait() # Wait for clean exit
            self.status_label.setText("Attack stopped by user")
            self.btn_stop_attack.setEnabled(False)
            self.lbl_attack_stats.setText("") # Clear stats
            QMessageBox.information(self, "Stopped", "Attack stopped.\nYou can restart scanning now.")

    def on_attack_finished(self, msg):
        self.status_label.setText(msg)
        self.btn_stop_attack.setEnabled(False)
        self.lbl_attack_stats.setText("") # Clear stats
        # Only show message if it wasn't manually stopped (logic could be improved but sufficient for now)
    
    def closeEvent(self, event):
        # Clean shutdown of threads
        if self.scanner:
            self.scanner.stop()
            self.scanner.wait()
        if self.attacker:
            self.attacker.stop()
            self.attacker.wait()
        if self.hunter:
            self.hunter.stop()
            self.hunter.wait()
        if self.monitor_interface:
            disable_monitor_mode(self.monitor_interface)
        event.accept()
