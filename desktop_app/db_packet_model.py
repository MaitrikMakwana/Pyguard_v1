"""
Database-backed packet model for PyGuard Desktop application.
Provides a virtual model for displaying packets from the database.
"""

from PyQt5.QtCore import QAbstractTableModel, Qt, QModelIndex
import logging

logger = logging.getLogger('desktop_app')

class DatabasePacketModel(QAbstractTableModel):
    """Database-backed model for packet display"""
    
    def __init__(self, db_manager, parent=None):
        super().__init__(parent)
        self.db_manager = db_manager
        self.headers = ["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"]
        self.page_size = 100
        self.current_page = 0
        self.total_count = 0
        self.cached_packets = []
        self.filters = {'capture_session': self.db_manager.capture_session}
        self.update_count()
        self.fetch_page(0)
    
    def rowCount(self, parent=None):
        return self.total_count
    
    def columnCount(self, parent=None):
        return len(self.headers)
    
    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.headers[section]
        return None
    
    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        
        # Calculate which page this row is on
        page = index.row() // self.page_size
        
        # If we don't have this page cached, fetch it
        if page != self.current_page:
            self.fetch_page(page)
        
        # Get the packet from the cache
        row_in_page = index.row() % self.page_size
        if row_in_page >= len(self.cached_packets):
            return None
        
        packet = self.cached_packets[row_in_page]
        col = index.column()
        
        if role == Qt.DisplayRole:
            # Return text data based on column
            if col == 0:
                return str(packet.get("frame_number", ""))
            elif col == 1:
                timestamp = packet.get("timestamp", "")
                if timestamp:
                    if isinstance(timestamp, str):
                        if " " in timestamp:
                            return timestamp.split(" ")[1].split(".")[0]
                        return timestamp
                    else:
                        # Format datetime object
                        return timestamp.strftime("%H:%M:%S")
                return ""
            elif col == 2:
                source = packet.get("src_ip", "")
                if packet.get("src_port"):
                    source += f":{packet['src_port']}"
                return source
            elif col == 3:
                destination = packet.get("dst_ip", "")
                if packet.get("dst_port"):
                    destination += f":{packet['dst_port']}"
                return destination
            elif col == 4:
                protocol = packet.get("protocol", "")
                if not protocol and packet.get("layers"):
                    protocol = packet["layers"][-1] if packet["layers"] else ""
                return protocol
            elif col == 5:
                return str(packet.get("size", 0))
            elif col == 6:
                return packet.get("summary", "")
        
        elif role == Qt.BackgroundRole:
            # Get color for this packet
            return self.parent().get_packet_color(packet)
        
        return None
    
    def update_count(self):
        """Update the total count of packets"""
        self.total_count = self.db_manager.get_packet_count(self.filters)
        self.layoutChanged.emit()
    
    def fetch_page(self, page):
        """Fetch a page of packets from the database"""
        offset = page * self.page_size
        self.cached_packets = self.db_manager.get_packets(
            filters=self.filters,
            limit=self.page_size,
            offset=offset,
            order_by='id',
            order='ASC'
        )
        self.current_page = page
    
    def set_filters(self, filters):
        """Set filters for the model"""
        # Always include capture session
        filters['capture_session'] = self.db_manager.capture_session
        self.filters = filters
        self.update_count()
        self.fetch_page(0)
        self.layoutChanged.emit()
    
    def refresh(self):
        """Refresh the model data"""
        self.update_count()
        self.fetch_page(self.current_page)
        self.layoutChanged.emit()