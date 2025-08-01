"""
PyGuard GUI application
"""

import sys
import logging
import time
import threading
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QComboBox, QTextEdit, QTabWidget,
    QGroupBox, QFormLayout, QSpinBox, QCheckBox, QFileDialog,
    QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox,
    QSplitter, QFrame, QLineEdit, QTableView, QAbstractItemView, QStyleFactory
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, pyqtSlot, QThread, QSize
from PyQt6.QtGui import QFont, QTextCursor, QAction, QIcon

import netifaces

logger = logging.getLogger(__name__)

class CaptureThread(QThread):
    """Thread for running packet capture"""
    
    status_update = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, capture_manager):
        super().__init__()
        self.capture_manager = capture_manager
        self.running = False
    
    def run(self):
        """Run the capture thread"""
        self.running = True
        
        try:
            # Start capture
            if not self.capture_manager.start():
                self.error_occurred.emit("Failed to start capture")
                self.running = False
                return
            
            # Emit status updates while running
            while self.running:
                stats = self.capture_manager.get_statistics()
                self.status_update.emit(stats)
                time.sleep(1)
        
        except Exception as e:
            logger.error(f"Error in capture thread: {e}")
            self.error_occurred.emit(f"Capture error: {e}")
        
        finally:
            # Stop capture if still running
            if self.running:
                self.capture_manager.stop()
            
            self.running = False
    
    def stop(self):
        """Stop the capture thread"""
        self.running = False
        self.wait()

class MainWindow(QMainWindow):
    """Modern main window for PyGuard GUI (PyQt6)"""
    def __init__(self, config, capture_manager):
        super().__init__()
        self.config = config
        self.capture_manager = capture_manager
        self.capture_thread = None
        self.setWindowTitle("PyGuard - Network Packet Capture")
        self.setGeometry(100, 100, 1400, 900)
        self.mode = "dark"
        self.init_ui()

    def init_ui(self):
        # Top Bar
        self.top_bar = QWidget()
        top_layout = QHBoxLayout(self.top_bar)
        top_layout.setContentsMargins(10, 10, 10, 10)
        self.start_btn = QPushButton(QIcon.fromTheme("media-playback-start"), "Start")
        self.start_btn.setToolTip("Start packet capture")
        self.stop_btn = QPushButton(QIcon.fromTheme("media-playback-stop"), "Stop")
        self.stop_btn.setToolTip("Stop packet capture")
        self.restart_btn = QPushButton(QIcon.fromTheme("view-refresh"), "Restart")
        self.restart_btn.setToolTip("Restart capture")
        self.save_btn = QPushButton(QIcon.fromTheme("document-save"), "Save")
        self.save_btn.setToolTip("Save captured packets")
        self.clear_btn = QPushButton(QIcon.fromTheme("edit-clear"), "Clear")
        self.clear_btn.setToolTip("Clear packet table")
        self.packet_count_combo = QComboBox()
        self.packet_count_combo.addItems(["100", "500", "1000", "5000", "Unlimited"])
        self.packet_count_combo.setToolTip("Set max packets to display")
        self.auto_scroll_check = QCheckBox("Auto-scroll")
        self.auto_scroll_check.setChecked(True)
        self.auto_scroll_check.setToolTip("Scroll to latest packet automatically")
        self.mode_switch_btn = QPushButton(QIcon.fromTheme("preferences-desktop-theme"), "Switch Mode")
        self.mode_switch_btn.setToolTip("Toggle dark/light mode")
        top_layout.addWidget(self.start_btn)
        top_layout.addWidget(self.stop_btn)
        top_layout.addWidget(self.restart_btn)
        top_layout.addWidget(self.save_btn)
        top_layout.addWidget(self.clear_btn)
        top_layout.addWidget(QLabel("Max Packets:"))
        top_layout.addWidget(self.packet_count_combo)
        top_layout.addWidget(self.auto_scroll_check)
        top_layout.addStretch(1)
        top_layout.addWidget(self.mode_switch_btn)

        # Sidebar Navigation Drawer
        self.sidebar = QWidget()
        sidebar_layout = QVBoxLayout(self.sidebar)
        sidebar_layout.setContentsMargins(10, 10, 10, 10)
        # Navigation buttons with icons
        self.nav_capture = QPushButton(QIcon.fromTheme("network-wired"), "Capture")
        self.nav_settings = QPushButton(QIcon.fromTheme("preferences-system"), "Settings")
        self.nav_stats = QPushButton(QIcon.fromTheme("view-statistics"), "Statistics")
        for btn in [self.nav_capture, self.nav_settings, self.nav_stats]:
            btn.setCheckable(True)
            btn.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
            btn.setStyleSheet("QPushButton { padding: 10px; border-radius: 8px; margin-bottom: 5px; } QPushButton:checked { background-color: #444; color: #43ea43; }")
            sidebar_layout.addWidget(btn)
        self.nav_capture.setChecked(True)
        # Section headers
        nav_header = QLabel("--- Controls ---")
        nav_header.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        sidebar_layout.addWidget(nav_header)
        # Grouped controls for Capture
        self.capture_controls = QWidget()
        capture_layout = QVBoxLayout(self.capture_controls)
        capture_layout.setSpacing(8)
        interface_label = QLabel("Network Interface:")
        interface_label.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        capture_layout.addWidget(interface_label)
        self.interface_combo = QComboBox()
        self.populate_interfaces()
        self.interface_combo.setToolTip("Select network interface to capture")
        self.interface_combo.setMaximumHeight(28)
        capture_layout.addWidget(self.interface_combo)
        filter_label = QLabel("Filter:")
        filter_label.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        capture_layout.addWidget(filter_label)
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Filter expression (e.g. tcp port 80)")
        self.filter_input.setToolTip("Enter BPF filter for packet capture")
        self.filter_input.setMaximumHeight(28)
        capture_layout.addWidget(self.filter_input)
        filter_btns = QHBoxLayout()
        self.apply_filter_btn = QPushButton(QIcon.fromTheme("system-run"), "Apply")
        self.apply_filter_btn.setToolTip("Apply filter to packet capture")
        self.clear_filter_btn = QPushButton(QIcon.fromTheme("edit-clear"), "Clear")
        self.clear_filter_btn.setToolTip("Clear filter expression")
        filter_btns.addWidget(self.apply_filter_btn)
        filter_btns.addWidget(self.clear_filter_btn)
        capture_layout.addLayout(filter_btns)
        # Protocol stats panel
        proto_stats = QGroupBox("Live Protocol Stats")
        proto_stats.setStyleSheet("QGroupBox { font-weight: bold; border: 1px solid #444; border-radius: 5px; margin-top: 10px; }")
        proto_layout = QVBoxLayout(proto_stats)
        self.tcp_stat = QLabel("TCP: 0")
        self.tcp_stat.setStyleSheet("color: #43ea43; font-weight: bold;")
        self.udp_stat = QLabel("UDP: 0")
        self.udp_stat.setStyleSheet("color: orange; font-weight: bold;")
        self.icmp_stat = QLabel("ICMP: 0")
        self.icmp_stat.setStyleSheet("color: #00bfff; font-weight: bold;")
        proto_layout.addWidget(self.tcp_stat)
        proto_layout.addWidget(self.udp_stat)
        proto_layout.addWidget(self.icmp_stat)
        capture_layout.addWidget(proto_stats)
        # Collapsible log viewer
        self.log_group = QGroupBox("Log Viewer")
        self.log_group.setCheckable(True)
        self.log_group.setChecked(True)
        self.log_group.setStyleSheet("QGroupBox { font-weight: bold; border: 1px solid #444; border-radius: 5px; margin-top: 10px; } QGroupBox::indicator { width: 20px; height: 20px; }")
        log_layout = QVBoxLayout(self.log_group)
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont("Courier New", 10))
        log_layout.addWidget(self.log_text)
        capture_layout.addWidget(self.log_group)
        self.capture_controls.setLayout(capture_layout)
        sidebar_layout.addWidget(self.capture_controls)
        sidebar_layout.addStretch(1)
        # Connect navigation
        self.nav_capture.clicked.connect(lambda: self.switch_section("capture"))
        self.nav_settings.clicked.connect(lambda: self.switch_section("settings"))
        self.nav_stats.clicked.connect(lambda: self.switch_section("stats"))
    def switch_section(self, section):
        self.nav_capture.setChecked(section == "capture")
        self.nav_settings.setChecked(section == "settings")
        self.nav_stats.setChecked(section == "stats")
        self.capture_controls.setVisible(section == "capture")
        # TODO: Show/hide main_area widgets for settings/stats

        # Main Area: Split left (packet table) and right (tabs)
        self.main_area = QSplitter()
        self.main_area.setOrientation(Qt.Orientation.Horizontal)
        # Left: Packet Table
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(10, 10, 10, 10)
        self.packet_table = QTableWidget(0, 7)
        self.packet_table.setHorizontalHeaderLabels([
            "No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"
        ])
        self.packet_table.setSortingEnabled(True)
        self.packet_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.packet_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.packet_table.setAlternatingRowColors(True)
        self.packet_table.setStyleSheet("QTableWidget { font-size: 15pt; } QHeaderView::section { background-color: #222; color: #fff; font-weight: bold; } QTableWidget::item { height: 40px; }")
        self.packet_table.setMinimumHeight(350)
        left_layout.addWidget(self.packet_table)
        left_panel.setLayout(left_layout)
        # Right: Tab Widget for analysis/info
        right_panel = QTabWidget()
        right_panel.setStyleSheet("QTabWidget::pane { border: 1px solid #444; border-radius: 5px; } QTabBar::tab { background: #222; color: #fff; padding: 12px; font-size: 12pt; border-radius: 5px; margin: 2px; }")
        # Packet Analysis Tab
        self.analysis_tab = QWidget()
        analysis_layout = QVBoxLayout(self.analysis_tab)
        self.analysis_label = QLabel("Packet Analysis will be shown here.")
        self.analysis_label.setWordWrap(True)
        analysis_layout.addWidget(self.analysis_label)
        right_panel.addTab(self.analysis_tab, "Packet Analysis")
        # Captured Packets Tab
        self.captured_tab = QWidget()
        captured_layout = QVBoxLayout(self.captured_tab)
        self.captured_label = QLabel("Summary of captured packets.")
        self.captured_label.setWordWrap(True)
        captured_layout.addWidget(self.captured_label)
        right_panel.addTab(self.captured_tab, "Captured Packets")
        # Advanced Filter Tab
        self.filter_tab = QWidget()
        filter_layout = QVBoxLayout(self.filter_tab)
        self.filter_label = QLabel("Advanced filter options and results.")
        self.filter_label.setWordWrap(True)
        filter_layout.addWidget(self.filter_label)
        right_panel.addTab(self.filter_tab, "Advanced Filter")
        # Info Tab
        self.info_tab = QWidget()
        info_layout = QVBoxLayout(self.info_tab)
        self.info_label = QLabel("Packet info and metadata.")
        self.info_label.setWordWrap(True)
        info_layout.addWidget(self.info_label)
        right_panel.addTab(self.info_tab, "Info")
        # Add panels to splitter
        self.main_area.addWidget(left_panel)
        self.main_area.addWidget(right_panel)
        self.main_area.setSizes([700, 700])
    def add_packet_row(self, packet):
        """Add a packet to the table and highlight by protocol"""
        from PyQt6.QtGui import QColor, QBrush
        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)
        protocol_color = None
        text_color = None
        for col, value in enumerate(packet):
            item = QTableWidgetItem(str(value))
            if col == 4:  # Protocol column
                proto = str(value).upper()
                if proto == "TCP":
                    protocol_color = QBrush(QColor("#43ea43"))
                    text_color = QBrush(QColor("#222"))
                elif proto == "UDP":
                    protocol_color = QBrush(QColor("orange"))
                    text_color = QBrush(QColor("#222"))
                elif proto == "ICMP":
                    protocol_color = QBrush(QColor("#00bfff"))
                    text_color = QBrush(QColor("#222"))
                else:
                    protocol_color = None
                    text_color = None
            # Apply color to all columns in the row for visibility
            if protocol_color and text_color:
                item.setBackground(protocol_color)
                item.setForeground(text_color)
            self.packet_table.setItem(row, col, item)
        # Auto-scroll if enabled
        if self.auto_scroll_check.isChecked():
            self.packet_table.scrollToBottom()

        # Splitter for sidebar and main area
        splitter = QSplitter()
        splitter.addWidget(self.sidebar)
        splitter.addWidget(self.main_area)
        splitter.setSizes([300, 1100])

        # Central widget layout
        central_widget = QWidget()
        central_layout = QVBoxLayout(central_widget)
        central_layout.setContentsMargins(0, 0, 0, 0)
        central_layout.addWidget(self.top_bar)
        central_layout.addWidget(splitter)
        self.setCentralWidget(central_widget)

        # Status bar
        self.statusBar().showMessage("Ready")

        # Mode switching
        self.mode_switch_btn.clicked.connect(self.switch_mode)
        self.apply_mode()

        # TODO: Connect buttons to backend logic

    def switch_mode(self):
        self.mode = "light" if self.mode == "dark" else "dark"
        self.apply_mode()

    def apply_mode(self):
        if self.mode == "dark":
            QApplication.setStyle(QStyleFactory.create("Fusion"))
            dark_palette = self._dark_palette()
            QApplication.instance().setPalette(dark_palette)
        else:
            QApplication.setStyle(QStyleFactory.create("Fusion"))
            QApplication.instance().setPalette(QApplication.style().standardPalette())

    def _dark_palette(self):
        palette = QApplication.palette()
        palette.setColor(palette.ColorRole.Window, Qt.GlobalColor.black)
        palette.setColor(palette.ColorRole.WindowText, Qt.GlobalColor.white)
        palette.setColor(palette.ColorRole.Base, Qt.GlobalColor.black)
        palette.setColor(palette.ColorRole.AlternateBase, Qt.GlobalColor.darkGray)
        palette.setColor(palette.ColorRole.ToolTipBase, Qt.GlobalColor.white)
        palette.setColor(palette.ColorRole.ToolTipText, Qt.GlobalColor.white)
        palette.setColor(palette.ColorRole.Text, Qt.GlobalColor.white)
        palette.setColor(palette.ColorRole.Button, Qt.GlobalColor.darkGray)
        palette.setColor(palette.ColorRole.ButtonText, Qt.GlobalColor.white)
        palette.setColor(palette.ColorRole.BrightText, Qt.GlobalColor.red)
        palette.setColor(palette.ColorRole.Highlight, Qt.GlobalColor.darkCyan)
        palette.setColor(palette.ColorRole.HighlightedText, Qt.GlobalColor.black)
        return palette

    # ...existing methods (populate_interfaces, etc.)...
    
    def create_capture_tab(self):
        """Create the capture tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Create interface selection group
        interface_group = QGroupBox("Network Interface")
        interface_layout = QHBoxLayout(interface_group)
        
        # Interface selection combo box
        self.interface_combo = QComboBox()
        self.populate_interfaces()
        interface_layout.addWidget(QLabel("Interface:"))
        interface_layout.addWidget(self.interface_combo, 1)
        
        # Refresh button
        refresh_button = QPushButton("Refresh")
        refresh_button.clicked.connect(self.populate_interfaces)
        interface_layout.addWidget(refresh_button)
        
        layout.addWidget(interface_group)
        
        # Create capture controls group
        controls_group = QGroupBox("Capture Controls")
        controls_layout = QHBoxLayout(controls_group)
        
        # Start button
        self.start_button = QPushButton("Start Capture")
        self.start_button.clicked.connect(self.start_capture)
        controls_layout.addWidget(self.start_button)
        
        # Stop button
        self.stop_button = QPushButton("Stop Capture")
        self.stop_button.clicked.connect(self.stop_capture)
        self.stop_button.setEnabled(False)
        controls_layout.addWidget(self.stop_button)
        
        layout.addWidget(controls_group)
        
        # Create capture status group
        status_group = QGroupBox("Capture Status")
        status_layout = QFormLayout(status_group)
        
        # Status labels
        self.status_label = QLabel("Stopped")
        status_layout.addRow("Status:", self.status_label)
        
        self.packets_label = QLabel("0")
        status_layout.addRow("Packets Captured:", self.packets_label)
        
        self.rate_label = QLabel("0/s")
        status_layout.addRow("Capture Rate:", self.rate_label)
        
        self.dropped_label = QLabel("0")
        status_layout.addRow("Packets Dropped:", self.dropped_label)
        
        self.queue_label = QLabel("0")
        status_layout.addRow("Queue Size:", self.queue_label)
        
        layout.addWidget(status_group)
        
        # Create log viewer
        log_group = QGroupBox("Log")
        log_layout = QVBoxLayout(log_group)
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont("Courier New", 10))
        log_layout.addWidget(self.log_text)
        
        layout.addWidget(log_group, 1)  # Give log viewer extra space
        
        return tab
    
    def create_settings_tab(self):
        """Create the settings tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Create capture settings group
        capture_group = QGroupBox("Capture Settings")
        capture_layout = QFormLayout(capture_group)
        
        # BPF filter
        self.bpf_filter = QTextEdit()
        self.bpf_filter.setPlaceholderText("Enter BPF filter (e.g., 'tcp port 80')")
        self.bpf_filter.setMaximumHeight(60)
        capture_layout.addRow("BPF Filter:", self.bpf_filter)
        
        # Promiscuous mode
        self.promiscuous_check = QCheckBox()
        self.promiscuous_check.setChecked(self.config.capture["promiscuous"])
        capture_layout.addRow("Promiscuous Mode:", self.promiscuous_check)
        
        # Snaplen
        self.snaplen_spin = QSpinBox()
        self.snaplen_spin.setRange(68, 65535)
        self.snaplen_spin.setValue(self.config.capture["snaplen"])
        capture_layout.addRow("Snaplen:", self.snaplen_spin)
        
        # Buffer size
        self.buffer_spin = QSpinBox()
        self.buffer_spin.setRange(1, 1000)
        self.buffer_spin.setValue(self.config.capture["buffer_size_mb"])
        capture_layout.addRow("Buffer Size (MB):", self.buffer_spin)
        
        # Processing threads
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 16)
        self.threads_spin.setValue(self.config.capture["processing_threads"])
        capture_layout.addRow("Processing Threads:", self.threads_spin)
        
        layout.addWidget(capture_group)
        
        # Create storage settings group
        storage_group = QGroupBox("Storage Settings")
        storage_layout = QFormLayout(storage_group)
        
        # Output directory
        self.output_dir = QLabel(self.config.output_dir)
        output_dir_layout = QHBoxLayout()
        output_dir_layout.addWidget(self.output_dir, 1)
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.browse_output_dir)
        output_dir_layout.addWidget(browse_button)
        storage_layout.addRow("Output Directory:", output_dir_layout)
        
        # PCAP settings
        self.pcap_check = QCheckBox()
        self.pcap_check.setChecked(self.config.pcap["enabled"])
        storage_layout.addRow("Enable PCAP:", self.pcap_check)
        
        self.pcap_rotate_size = QSpinBox()
        self.pcap_rotate_size.setRange(1, 1000)
        self.pcap_rotate_size.setValue(self.config.pcap["rotate_size_mb"])
        storage_layout.addRow("PCAP Rotate Size (MB):", self.pcap_rotate_size)
        
        self.pcap_rotate_interval = QSpinBox()
        self.pcap_rotate_interval.setRange(1, 1440)
        self.pcap_rotate_interval.setValue(self.config.pcap["rotate_interval_minutes"])
        storage_layout.addRow("PCAP Rotate Interval (min):", self.pcap_rotate_interval)
        
        # Database settings
        self.db_check = QCheckBox()
        self.db_check.setChecked(self.config.database["enabled"])
        storage_layout.addRow("Enable Database:", self.db_check)
        
        self.db_host = QTextEdit()
        self.db_host.setPlaceholderText("localhost")
        self.db_host.setText(self.config.database["host"])
        self.db_host.setMaximumHeight(30)
        storage_layout.addRow("Database Host:", self.db_host)
        
        self.db_port = QSpinBox()
        self.db_port.setRange(1, 65535)
        self.db_port.setValue(self.config.database["port"])
        storage_layout.addRow("Database Port:", self.db_port)
        
        self.db_name = QTextEdit()
        self.db_name.setPlaceholderText("pyguard")
        self.db_name.setText(self.config.database["name"])
        self.db_name.setMaximumHeight(30)
        storage_layout.addRow("Database Name:", self.db_name)
        
        layout.addWidget(storage_group)
        
        # Create buttons
        buttons_layout = QHBoxLayout()
        
        save_button = QPushButton("Save Settings")
        save_button.clicked.connect(self.save_settings)
        buttons_layout.addWidget(save_button)
        
        reset_button = QPushButton("Reset to Defaults")
        reset_button.clicked.connect(self.reset_settings)
        buttons_layout.addWidget(reset_button)
        
        layout.addLayout(buttons_layout)
        
        # Add stretch to push everything to the top
        layout.addStretch(1)
        
        return tab
    
    def create_stats_tab(self):
        """Create the statistics tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Create system resources group
        resources_group = QGroupBox("System Resources")
        resources_layout = QFormLayout(resources_group)
        
        self.cpu_label = QLabel("0%")
        resources_layout.addRow("CPU Usage:", self.cpu_label)
        
        self.memory_label = QLabel("0%")
        resources_layout.addRow("Memory Usage:", self.memory_label)
        
        self.process_cpu_label = QLabel("0%")
        resources_layout.addRow("Process CPU:", self.process_cpu_label)
        
        self.process_memory_label = QLabel("0%")
        resources_layout.addRow("Process Memory:", self.process_memory_label)
        
        layout.addWidget(resources_group)
        
        # Create capture statistics group
        capture_stats_group = QGroupBox("Capture Statistics")
        capture_stats_layout = QFormLayout(capture_stats_group)
        
        self.elapsed_label = QLabel("00:00:00")
        capture_stats_layout.addRow("Elapsed Time:", self.elapsed_label)
        
        self.total_packets_label = QLabel("0")
        capture_stats_layout.addRow("Total Packets:", self.total_packets_label)
        
        self.avg_rate_label = QLabel("0/s")
        capture_stats_layout.addRow("Average Rate:", self.avg_rate_label)
        
        self.current_rate_label = QLabel("0/s")
        capture_stats_layout.addRow("Current Rate:", self.current_rate_label)
        
        self.db_packets_label = QLabel("0")
        capture_stats_layout.addRow("DB Packets:", self.db_packets_label)
        
        self.csv_packets_label = QLabel("0")
        capture_stats_layout.addRow("CSV Packets:", self.csv_packets_label)
        
        layout.addWidget(capture_stats_group)
        
        # Add stretch to push everything to the top
        layout.addStretch(1)
        
        return tab
    
    def populate_interfaces(self):
        """Populate the interface combo box"""
        self.interface_combo.clear()
        
        try:
            # Get list of network interfaces
            interfaces = netifaces.interfaces()
            
            for interface in interfaces:
                # Skip loopback interface on non-Windows systems
                if interface == 'lo' and sys.platform != 'win32':
                    continue
                
                # Add interface to combo box
                self.interface_combo.addItem(interface)
            
            # Select current interface from config
            index = self.interface_combo.findText(self.config.interface)
            if index >= 0:
                self.interface_combo.setCurrentIndex(index)
        
        except Exception as e:
            logger.error(f"Error populating interfaces: {e}")
            self.statusBar().showMessage(f"Error: {e}")
    
    def browse_output_dir(self):
        """Browse for output directory"""
        directory = QFileDialog.getExistingDirectory(
            self, "Select Output Directory", self.config.output_dir
        )
        
        if directory:
            self.output_dir.setText(directory)
    
    def save_settings(self):
        """Save settings to configuration"""
        try:
            # Update configuration with UI values
            self.config.interface = self.interface_combo.currentText()
            self.config.capture["bpf_filter"] = self.bpf_filter.toPlainText()
            self.config.capture["promiscuous"] = self.promiscuous_check.isChecked()
            self.config.capture["snaplen"] = self.snaplen_spin.value()
            self.config.capture["buffer_size_mb"] = self.buffer_spin.value()
            self.config.capture["processing_threads"] = self.threads_spin.value()
            
            self.config.output_dir = self.output_dir.text()
            
            self.config.pcap["enabled"] = self.pcap_check.isChecked()
            self.config.pcap["rotate_size_mb"] = self.pcap_rotate_size.value()
            self.config.pcap["rotate_interval_minutes"] = self.pcap_rotate_interval.value()
            
            self.config.database["enabled"] = self.db_check.isChecked()
            self.config.database["host"] = self.db_host.toPlainText()
            self.config.database["port"] = self.db_port.value()
            self.config.database["name"] = self.db_name.toPlainText()
            
            # Save configuration to file
            self.config.save("config.yaml")
            
            self.statusBar().showMessage("Settings saved successfully")
        
        except Exception as e:
            logger.error(f"Error saving settings: {e}")
            self.statusBar().showMessage(f"Error saving settings: {e}")
            QMessageBox.critical(self, "Error", f"Error saving settings: {e}")
    
    def reset_settings(self):
        """Reset settings to defaults"""
        # Confirm reset
        reply = QMessageBox.question(
            self, "Reset Settings",
            "Are you sure you want to reset all settings to defaults?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # Create new config with defaults
            from pyguard.core.config import Config
            self.config = Config()
            
            # Update UI with default values
            self.populate_interfaces()
            
            self.bpf_filter.setPlainText(self.config.capture["bpf_filter"])
            self.promiscuous_check.setChecked(self.config.capture["promiscuous"])
            self.snaplen_spin.setValue(self.config.capture["snaplen"])
            self.buffer_spin.setValue(self.config.capture["buffer_size_mb"])
            self.threads_spin.setValue(self.config.capture["processing_threads"])
            
            self.output_dir.setText(self.config.output_dir)
            
            self.pcap_check.setChecked(self.config.pcap["enabled"])
            self.pcap_rotate_size.setValue(self.config.pcap["rotate_size_mb"])
            self.pcap_rotate_interval.setValue(self.config.pcap["rotate_interval_minutes"])
            
            self.db_check.setChecked(self.config.database["enabled"])
            self.db_host.setText(self.config.database["host"])
            self.db_port.setValue(self.config.database["port"])
            self.db_name.setText(self.config.database["name"])
            
            self.statusBar().showMessage("Settings reset to defaults")
    
    def start_capture(self):
        """Start packet capture"""
        try:
            # Update configuration with current interface
            self.config.interface = self.interface_combo.currentText()
            
            # Create capture thread
            self.capture_thread = CaptureThread(self.capture_manager)
            self.capture_thread.status_update.connect(self.update_status)
            self.capture_thread.error_occurred.connect(self.handle_error)
            self.capture_thread.start()
            
            # Update UI
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.status_label.setText("Running")
            self.statusBar().showMessage("Capture started")
            
            # Log message
            self.log_message(f"Capture started on interface {self.config.interface}")
        
        except Exception as e:
            logger.error(f"Error starting capture: {e}")
            self.statusBar().showMessage(f"Error: {e}")
            QMessageBox.critical(self, "Error", f"Error starting capture: {e}")
    
    def stop_capture(self):
        """Stop packet capture"""
        try:
            if self.capture_thread and self.capture_thread.isRunning():
                # Stop capture thread
                self.capture_thread.stop()
                
                # Update UI
                self.start_button.setEnabled(True)
                self.stop_button.setEnabled(False)
                self.status_label.setText("Stopped")
                self.statusBar().showMessage("Capture stopped")
                
                # Log message
                self.log_message("Capture stopped")
        
        except Exception as e:
            logger.error(f"Error stopping capture: {e}")
            self.statusBar().showMessage(f"Error: {e}")
            QMessageBox.critical(self, "Error", f"Error stopping capture: {e}")
    
    def update_status(self, stats):
        """Update status with capture statistics"""
        # Update capture status
        self.packets_label.setText(str(stats.get("packets_processed", 0)))
        self.rate_label.setText(f"{stats.get('packets_per_second', 0):.1f}/s")
        self.dropped_label.setText(str(stats.get("dropped", 0)))
        self.queue_label.setText(str(stats.get("queue_size", 0)))
        
        # Update statistics tab
        elapsed = stats.get("elapsed_time", 0)
        hours = int(elapsed / 3600)
        minutes = int((elapsed % 3600) / 60)
        seconds = int(elapsed % 60)
        self.elapsed_label.setText(f"{hours:02d}:{minutes:02d}:{seconds:02d}")
        
        self.total_packets_label.setText(str(stats.get("packets_processed", 0)))
        self.avg_rate_label.setText(f"{stats.get('packets_per_second', 0):.1f}/s")
        self.current_rate_label.setText(f"{stats.get('current_rate', 0):.1f}/s")
        self.db_packets_label.setText(str(stats.get("packets_stored_db", 0)))
        self.csv_packets_label.setText(str(stats.get("packets_stored_csv", 0)))
        
        # Update system resources
        system_load = stats.get("system_load", {})
        self.cpu_label.setText(f"{system_load.get('cpu_percent', 0):.1f}%")
        self.memory_label.setText(f"{system_load.get('memory_percent', 0):.1f}%")
        self.process_cpu_label.setText(f"{system_load.get('process_cpu_percent', 0):.1f}%")
        self.process_memory_label.setText(f"{system_load.get('process_memory_percent', 0):.1f}%")
    
    def update_statistics(self):
        """Update statistics periodically"""
        if not self.capture_thread or not self.capture_thread.isRunning():
            return
        
        # Statistics are updated by the capture thread
        pass
    
    def handle_error(self, error_message):
        """Handle error from capture thread"""
        self.statusBar().showMessage(f"Error: {error_message}")
        self.log_message(f"ERROR: {error_message}")
        
        # Stop capture if running
        if self.capture_thread and self.capture_thread.isRunning():
            self.stop_capture()
    
    def log_message(self, message):
        """Add message to log viewer"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        self.log_text.append(f"[{timestamp}] {message}")
        
        # Scroll to bottom
        self.log_text.moveCursor(QTextCursor.End)
    
    def closeEvent(self, event):
        """Handle window close event"""
        # Stop capture if running
        if self.capture_thread and self.capture_thread.isRunning():
            reply = QMessageBox.question(
                self, "Exit",
                "Capture is still running. Do you want to stop it and exit?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                self.stop_capture()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()

def start_gui(config, capture_manager):
    """Start the PyGuard GUI application"""
    app = QApplication(sys.argv)
    window = MainWindow(config, capture_manager)
    window.show()
    return app.exec_()