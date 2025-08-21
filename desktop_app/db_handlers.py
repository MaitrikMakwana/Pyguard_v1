"""
Database-specific handlers for PyGuard Desktop application.
"""

from PyQt5.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QComboBox, QLineEdit, QDateTimeEdit, QPushButton, QMessageBox
from PyQt5.QtCore import QDateTime, Qt
import logging

logger = logging.getLogger('desktop_app')

def on_db_packet_selected(self, selected, deselected):
    """Handle selection in database-backed model"""
    indexes = selected.indexes()
    if not indexes:
        return
    
    # Get the row number
    row = indexes[0].row()
    
    # Calculate which page this row is on
    page = row // self.packet_model.page_size
    
    # If we don't have this page cached, fetch it
    if page != self.packet_model.current_page:
        self.packet_model.fetch_page(page)
    
    # Get the packet from the cache
    row_in_page = row % self.packet_model.page_size
    if row_in_page >= len(self.packet_model.cached_packets):
        return
    
    packet = self.packet_model.cached_packets[row_in_page]
    self.display_packet_details(packet)
    
    # Update status bar with packet info
    protocol = packet.get("protocol", "")
    if not protocol and packet.get("layers"):
        protocol = packet["layers"][-1] if packet["layers"] else ""
    
    src = packet.get("src_ip", "")
    if packet.get("src_port"):
        src += f":{packet['src_port']}"
    
    dst = packet.get("dst_ip", "")
    if packet.get("dst_port"):
        dst += f":{packet['dst_port']}"
    
    self.statusBar().showMessage(
        f"Selected: {protocol} packet from {src} to {dst}, {packet.get('size', 0)} bytes"
    )

def show_db_packet_context_menu(self, position):
    """Show context menu for database-backed packet list"""
    # Get selected row
    indexes = self.packet_table.selectionModel().selectedIndexes()
    if not indexes:
        return
    
    # Get the row number
    row = indexes[0].row()
    
    # Calculate which page this row is on
    page = row // self.packet_model.page_size
    
    # If we don't have this page cached, fetch it
    if page != self.packet_model.current_page:
        self.packet_model.fetch_page(page)
    
    # Get the packet from the cache
    row_in_page = row % self.packet_model.page_size
    if row_in_page >= len(self.packet_model.cached_packets):
        return
    
    packet = self.packet_model.cached_packets[row_in_page]
    
    # Create context menu
    from PyQt5.QtWidgets import QMenu, QAction
    context_menu = QMenu(self)
    
    # Add actions
    copy_action = QAction("Copy Packet Details", self)
    copy_action.triggered.connect(lambda: self.copy_db_packet_to_clipboard(packet))
    context_menu.addAction(copy_action)
    
    filter_by_ip_action = QAction("Filter by IP", self)
    filter_by_ip_action.triggered.connect(lambda: self.filter_db_by_ip(packet))
    context_menu.addAction(filter_by_ip_action)
    
    filter_by_protocol_action = QAction("Filter by Protocol", self)
    filter_by_protocol_action.triggered.connect(lambda: self.filter_db_by_protocol(packet))
    context_menu.addAction(filter_by_protocol_action)
    
    # Show context menu
    context_menu.exec_(self.packet_table.mapToGlobal(position))

def copy_db_packet_to_clipboard(self, packet):
    """Copy database packet details to clipboard"""
    if packet:
        # Format packet details as text
        details = []
        details.append(f"Packet #{packet.get('frame_number', '')}")
        details.append(f"Time: {packet.get('timestamp', '')}")
        details.append(f"Source: {packet.get('src_ip', '')}")
        if packet.get('src_port'):
            details.append(f"Source Port: {packet.get('src_port')}")
        details.append(f"Destination: {packet.get('dst_ip', '')}")
        if packet.get('dst_port'):
            details.append(f"Destination Port: {packet.get('dst_port')}")
        details.append(f"Protocol: {packet.get('protocol', '')}")
        details.append(f"Length: {packet.get('size', 0)} bytes")
        details.append(f"Summary: {packet.get('summary', '')}")
        
        # Copy to clipboard
        from PyQt5.QtWidgets import QApplication
        QApplication.clipboard().setText("\n".join(details))
        self.statusBar().showMessage("Packet details copied to clipboard")

def filter_db_by_ip(self, packet):
    """Filter database packets by IP address"""
    # Create dialog to choose source or destination
    from PyQt5.QtWidgets import QDialog, QVBoxLayout, QRadioButton, QPushButton, QHBoxLayout
    dialog = QDialog(self)
    dialog.setWindowTitle("Filter by IP")
    
    layout = QVBoxLayout(dialog)
    
    # Add radio buttons for source and destination
    src_radio = QRadioButton(f"Source IP: {packet.get('src_ip', '')}")
    dst_radio = QRadioButton(f"Destination IP: {packet.get('dst_ip', '')}")
    src_radio.setChecked(True)
    
    layout.addWidget(src_radio)
    layout.addWidget(dst_radio)
    
    # Add buttons
    button_layout = QHBoxLayout()
    ok_button = QPushButton("OK")
    cancel_button = QPushButton("Cancel")
    button_layout.addWidget(ok_button)
    button_layout.addWidget(cancel_button)
    layout.addLayout(button_layout)
    
    # Connect buttons
    ok_button.clicked.connect(dialog.accept)
    cancel_button.clicked.connect(dialog.reject)
    
    # Show dialog
    if dialog.exec_() == QDialog.Accepted:
        # Apply filter
        filters = {'capture_session': self.db_manager.capture_session}
        
        if src_radio.isChecked():
            filters['src_ip'] = packet.get('src_ip', '')
        else:
            filters['dst_ip'] = packet.get('dst_ip', '')
        
        # Apply filters
        self.packet_model.set_filters(filters)
        
        # Update status
        self.statusBar().showMessage(f"Filtered by IP: {filters.get('src_ip') or filters.get('dst_ip')}")

def filter_db_by_protocol(self, packet):
    """Filter database packets by protocol"""
    protocol = packet.get('protocol', '')
    if not protocol and packet.get('layers'):
        protocol = packet['layers'][-1] if packet['layers'] else ''
    
    if protocol:
        # Apply filter
        filters = {
            'capture_session': self.db_manager.capture_session,
            'protocol': protocol
        }
        
        # Apply filters
        self.packet_model.set_filters(filters)
        
        # Update status
        self.statusBar().showMessage(f"Filtered by protocol: {protocol}")

def show_db_filter_dialog(self):
    """Show database filter dialog"""
    dialog = QDialog(self)
    dialog.setWindowTitle("Database Filter")
    dialog.setMinimumWidth(400)
    
    layout = QVBoxLayout(dialog)
    
    # Protocol filter
    protocol_layout = QHBoxLayout()
    protocol_layout.addWidget(QLabel("Protocol:"))
    protocol_combo = QComboBox()
    protocol_combo.addItem("All")
    protocol_combo.addItems(["TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP", "HTTPS"])
    protocol_layout.addWidget(protocol_combo)
    layout.addLayout(protocol_layout)
    
    # Source IP filter
    src_ip_layout = QHBoxLayout()
    src_ip_layout.addWidget(QLabel("Source IP:"))
    src_ip_edit = QLineEdit()
    src_ip_layout.addWidget(src_ip_edit)
    layout.addLayout(src_ip_layout)
    
    # Destination IP filter
    dst_ip_layout = QHBoxLayout()
    dst_ip_layout.addWidget(QLabel("Destination IP:"))
    dst_ip_edit = QLineEdit()
    dst_ip_layout.addWidget(dst_ip_edit)
    layout.addLayout(dst_ip_layout)
    
    # Time range filter
    time_layout = QHBoxLayout()
    time_layout.addWidget(QLabel("Time Range:"))
    start_time_edit = QDateTimeEdit()
    start_time_edit.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
    start_time_edit.setDateTime(QDateTime.currentDateTime().addSecs(-3600))  # Last hour
    time_layout.addWidget(start_time_edit)
    time_layout.addWidget(QLabel("to"))
    end_time_edit = QDateTimeEdit()
    end_time_edit.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
    end_time_edit.setDateTime(QDateTime.currentDateTime())
    time_layout.addWidget(end_time_edit)
    layout.addLayout(time_layout)
    
    # Buttons
    button_layout = QHBoxLayout()
    apply_button = QPushButton("Apply")
    clear_button = QPushButton("Clear Filters")
    cancel_button = QPushButton("Cancel")
    button_layout.addWidget(apply_button)
    button_layout.addWidget(clear_button)
    button_layout.addWidget(cancel_button)
    layout.addLayout(button_layout)
    
    # Connect buttons
    def apply_filters():
        """Apply filters to database model"""
        filters = {'capture_session': self.db_manager.capture_session}
        
        # Protocol filter
        if protocol_combo.currentText() != "All":
            filters['protocol'] = protocol_combo.currentText()
        
        # Source IP filter
        if src_ip_edit.text().strip():
            filters['src_ip'] = src_ip_edit.text().strip()
        
        # Destination IP filter
        if dst_ip_edit.text().strip():
            filters['dst_ip'] = dst_ip_edit.text().strip()
        
        # Time range filter
        filters['start_time'] = start_time_edit.dateTime().toPython()
        filters['end_time'] = end_time_edit.dateTime().toPython()
        
        # Apply filters
        self.packet_model.set_filters(filters)
        
        # Update status
        self.statusBar().showMessage("Database filter applied")
        
        # Close dialog
        dialog.accept()
    
    def clear_filters():
        """Clear all filters"""
        protocol_combo.setCurrentText("All")
        src_ip_edit.clear()
        dst_ip_edit.clear()
        start_time_edit.setDateTime(QDateTime.currentDateTime().addSecs(-3600))
        end_time_edit.setDateTime(QDateTime.currentDateTime())
    
    apply_button.clicked.connect(apply_filters)
    clear_button.clicked.connect(clear_filters)
    cancel_button.clicked.connect(dialog.reject)
    
    # Show dialog
    dialog.exec_()

def clear_database(self):
    """Clear packets from database"""
    if not hasattr(self, 'db_manager') or not self.db_manager or not self.db_manager.enabled:
        return
    
    # Confirm with user
    reply = QMessageBox.question(
        self, "Clear Database",
        "Are you sure you want to clear all packets from the database?",
        QMessageBox.Yes | QMessageBox.No, QMessageBox.No
    )
    
    if reply == QMessageBox.Yes:
        # Clear database
        if self.db_manager.clear_packets(self.db_manager.capture_session):
            # Refresh model
            self.packet_model.refresh()
            
            # Update window title
            self.setWindowTitle("PyGuard Desktop - 0 packets captured")
            
            # Update status bar
            self.statusBar().showMessage("Database cleared")
        else:
            # Show error
            QMessageBox.critical(
                self, "Error",
                "Failed to clear database. See log for details.",
                QMessageBox.Ok
            )

def add_database_controls(self):
    """Add database-specific controls to the UI"""
    if not hasattr(self, 'db_manager') or not self.db_manager or not self.db_manager.enabled:
        return
    
    # Add database mode indicator to status bar
    self.db_mode_label = QLabel("DB Mode")
    self.db_mode_label.setStyleSheet("color: #2196F3; font-weight: bold;")
    self.statusBar().addPermanentWidget(self.db_mode_label)
    
    # Add database controls to toolbar
    self.toolbar.addSeparator()
    
    # Add filter button
    self.db_filter_button = QPushButton("DB Filter")
    self.db_filter_button.setToolTip("Filter packets in database")
    self.db_filter_button.clicked.connect(self.show_db_filter_dialog)
    self.toolbar.addWidget(self.db_filter_button)
    
    # Add refresh button
    self.db_refresh_button = QPushButton("Refresh")
    self.db_refresh_button.setToolTip("Refresh packet display from database")
    self.db_refresh_button.clicked.connect(lambda: self.packet_model.refresh())
    self.toolbar.addWidget(self.db_refresh_button)
    
    # Add clear button
    self.db_clear_button = QPushButton("Clear DB")
    self.db_clear_button.setToolTip("Clear packets from database")
    self.db_clear_button.clicked.connect(self.clear_database)
    self.toolbar.addWidget(self.db_clear_button)
    
    # Add session ID button
    self.session_id_button = QPushButton("Session ID")
    self.session_id_button.setToolTip("Show current capture session ID")
    self.session_id_button.clicked.connect(self.show_session_id)
    self.toolbar.addWidget(self.session_id_button)

def show_session_id(self):
    """Show the current capture session ID"""
    if not hasattr(self, 'db_manager') or not self.db_manager or not self.db_manager.enabled:
        QMessageBox.information(
            self, "Session ID",
            "Database is not enabled. No session ID available.",
            QMessageBox.Ok
        )
        return
    
    session_id = self.db_manager.capture_session
    
    # Get packet count for this session
    packet_count = self.db_manager.get_packet_count({'capture_session': session_id})
    
    # Create a dialog to display and copy the session ID
    from PyQt5.QtWidgets import QDialog, QVBoxLayout, QLabel, QLineEdit, QPushButton, QHBoxLayout
    
    dialog = QDialog(self)
    dialog.setWindowTitle("Capture Session ID")
    dialog.setMinimumWidth(500)
    
    layout = QVBoxLayout(dialog)
    
    # Add explanation
    layout.addWidget(QLabel("Current capture session ID:"))
    
    # Add session ID in a text field that can be copied
    session_field = QLineEdit(session_id)
    session_field.setReadOnly(True)
    layout.addWidget(session_field)
    
    # Add packet count information
    layout.addWidget(QLabel(f"Packets in this session: {packet_count:,}"))
    
    # Add explanation of how to use it
    layout.addWidget(QLabel("Use this ID in SQL queries to filter packets from this capture session:"))
    
    # Add example SQL queries
    layout.addWidget(QLabel("Example queries:"))
    
    # Query 1: Select all packets
    example_query1 = f"SELECT * FROM packets WHERE capture_session = '{session_id}' ORDER BY timestamp DESC LIMIT 100;"
    query_field1 = QLineEdit(example_query1)
    query_field1.setReadOnly(True)
    layout.addWidget(query_field1)
    
    # Query 2: Count by protocol
    example_query2 = f"SELECT protocol, COUNT(*) FROM packets WHERE capture_session = '{session_id}' GROUP BY protocol ORDER BY COUNT(*) DESC;"
    query_field2 = QLineEdit(example_query2)
    query_field2.setReadOnly(True)
    layout.addWidget(query_field2)
    
    # Add buttons
    button_layout = QHBoxLayout()
    
    copy_id_button = QPushButton("Copy Session ID")
    copy_id_button.clicked.connect(lambda: self.copy_to_clipboard(session_id))
    
    copy_query1_button = QPushButton("Copy Query 1")
    copy_query1_button.clicked.connect(lambda: self.copy_to_clipboard(example_query1))
    
    copy_query2_button = QPushButton("Copy Query 2")
    copy_query2_button.clicked.connect(lambda: self.copy_to_clipboard(example_query2))
    
    close_button = QPushButton("Close")
    close_button.clicked.connect(dialog.accept)
    
    button_layout.addWidget(copy_id_button)
    button_layout.addWidget(copy_query1_button)
    button_layout.addWidget(copy_query2_button)
    button_layout.addWidget(close_button)
    
    layout.addLayout(button_layout)
    
    # Show dialog
    dialog.exec_()

def copy_to_clipboard(self, text):
    """Copy text to clipboard"""
    from PyQt5.QtWidgets import QApplication
    QApplication.clipboard().setText(text)
    self.statusBar().showMessage(f"Copied to clipboard", 3000)