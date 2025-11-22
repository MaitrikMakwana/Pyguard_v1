"""
IDS Analysis Widget - Presents results returned by the IDS microservice.
"""

import logging
from datetime import datetime
from typing import Dict, Optional

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QGroupBox,
    QFormLayout,
    QPushButton,
    QTextEdit,
)

logger = logging.getLogger(__name__)


class IDSAnalysisWidget(QWidget):
    """Widget for displaying IDS analysis results within the desktop application."""

    analysisRequested = pyqtSignal()
    serviceCheckRequested = pyqtSignal()
    exportRequested = pyqtSignal()
    clearRequested = pyqtSignal()

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.results: Optional[Dict] = None
        self._setup_ui()
        self._set_idle_state()

    # ------------------------------------------------------------------ #
    # UI setup
    # ------------------------------------------------------------------ #
    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(12)

        # Status label
        self.status_label = QLabel("IDS analysis has not been run yet.")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        # Summary statistics
        self.summary_group = QGroupBox("Summary Statistics")
        summary_layout = QFormLayout()
        summary_layout.setLabelAlignment(Qt.AlignLeft)

        self.total_flows_label = QLabel("0")
        self.attack_flows_label = QLabel("0")
        self.benign_flows_label = QLabel("0")
        self.avg_confidence_label = QLabel("0.00")

        summary_layout.addRow("Total Flows:", self.total_flows_label)
        summary_layout.addRow("Attack Flows:", self.attack_flows_label)
        summary_layout.addRow("Benign Flows:", self.benign_flows_label)
        summary_layout.addRow("Avg Confidence:", self.avg_confidence_label)

        self.summary_group.setLayout(summary_layout)
        layout.addWidget(self.summary_group)

        # Attack distribution
        self.distribution_group = QGroupBox("Attack Distribution")
        distribution_layout = QVBoxLayout()

        self.distribution_text = QTextEdit()
        self.distribution_text.setReadOnly(True)
        self.distribution_text.setMinimumHeight(120)
        distribution_layout.addWidget(self.distribution_text)

        self.top_attacks_text = QTextEdit()
        self.top_attacks_text.setReadOnly(True)
        self.top_attacks_text.setMinimumHeight(100)
        distribution_layout.addWidget(self.top_attacks_text)

        self.distribution_group.setLayout(distribution_layout)
        layout.addWidget(self.distribution_group)

        # Detailed results table
        self.results_group = QGroupBox("Detailed Results (First 100 flows)")
        results_layout = QVBoxLayout()

        self.results_table = QTableWidget(0, 5)
        self.results_table.setHorizontalHeaderLabels(
            ["Flow ID", "Source IP", "Destination IP", "Predicted Label", "Confidence"]
        )
        header = self.results_table.horizontalHeader()
        header.setStretchLastSection(True)
        self.results_table.setColumnWidth(0, 80)
        self.results_table.setColumnWidth(1, 140)
        self.results_table.setColumnWidth(2, 140)
        self.results_table.setColumnWidth(3, 130)
        self.results_table.setColumnWidth(4, 100)

        results_layout.addWidget(self.results_table)
        self.results_group.setLayout(results_layout)
        layout.addWidget(self.results_group, 1)

        # Action buttons
        buttons_layout = QHBoxLayout()
        buttons_layout.setSpacing(10)

        self.check_service_btn = QPushButton("Service Status")
        self.check_service_btn.clicked.connect(self._emit_service_check)
        buttons_layout.addWidget(self.check_service_btn)

        self.analyze_btn = QPushButton("Analyze Current Capture")
        self.analyze_btn.clicked.connect(self._emit_analysis_request)
        buttons_layout.addWidget(self.analyze_btn)

        self.export_btn = QPushButton("Export Results")
        self.export_btn.clicked.connect(self._emit_export_request)
        self.export_btn.setEnabled(False)
        buttons_layout.addWidget(self.export_btn)

        self.clear_btn = QPushButton("Clear Results")
        self.clear_btn.clicked.connect(self._on_clear_clicked)
        buttons_layout.addWidget(self.clear_btn)

        layout.addLayout(buttons_layout)

    # ------------------------------------------------------------------ #
    # Status helpers
    # ------------------------------------------------------------------ #
    def _set_idle_state(self) -> None:
        self._update_status(
            "IDS analysis has not been run yet.",
            background="#f0f0f0",
            foreground="#333333",
        )
        self.export_btn.setEnabled(False)

    def set_info_state(self, message: str) -> None:
        """Show an informational status message without disabling actions."""
        self._update_status(
            message,
            background="#e1f5fe",
            foreground="#01579b",
        )
        self.analyze_btn.setEnabled(True)
        self.export_btn.setEnabled(bool(self.results))

    def set_busy_state(self, message: str = "Analyzing capture with IDS...") -> None:
        self._update_status(
            message,
            background="#fff3cd",
            foreground="#856404",
        )
        self.analyze_btn.setEnabled(False)
        self.export_btn.setEnabled(False)

    def set_error_state(self, message: str) -> None:
        self._update_status(
            message,
            background="#f8d7da",
            foreground="#721c24",
        )
        self.analyze_btn.setEnabled(True)
        self.export_btn.setEnabled(bool(self.results))

    def _update_status(self, text: str, background: str, foreground: str) -> None:
        self.status_label.setText(text)
        self.status_label.setStyleSheet(
            f"""
            QLabel {{
                background-color: {background};
                color: {foreground};
                border-radius: 4px;
                padding: 8px;
                font-weight: bold;
            }}
            """
        )

    # ------------------------------------------------------------------ #
    # Button callbacks
    # ------------------------------------------------------------------ #
    def _emit_service_check(self) -> None:
        self.serviceCheckRequested.emit()

    def _emit_analysis_request(self) -> None:
        self.analysisRequested.emit()

    def _emit_export_request(self) -> None:
        if self.results:
            self.exportRequested.emit()

    def _on_clear_clicked(self) -> None:
        self.clear()
        self.clearRequested.emit()

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def display_results(self, result_payload: Dict) -> None:
        """
        Display IDS analysis results.

        The payload is expected to contain:
            - summary: normalized summary dictionary
            - raw: raw IDS response (optional, passed through)
        """
        logger.info("IDS Analysis Widget: display_results called")
        if not result_payload:
            logger.warning("display_results called without payload")
            self.set_error_state("No results available to display.")
            return

        self.results = result_payload
        summary = result_payload.get("summary") or {}
        logger.debug(f"Summary keys: {list(summary.keys())}")
        logger.debug(f"Total flows: {summary.get('total_flows', 'N/A')}")
        logger.debug(f"Detailed results count: {len(summary.get('detailed_results', []))}")

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._update_status(
            f"Analysis complete - Last updated {timestamp}",
            background="#d4edda",
            foreground="#155724",
        )

        # Summary statistics
        total_flows = summary.get("total_flows", 0) or 0
        attack_flows = summary.get("attack_flows", 0) or 0
        benign_flows = summary.get("benign_flows", 0) or 0
        avg_conf = summary.get("average_confidence", 0.0) or 0.0

        self.total_flows_label.setText(f"{total_flows:,}")
        self.attack_flows_label.setText(f"{attack_flows:,}")
        self.benign_flows_label.setText(f"{benign_flows:,}")
        self.avg_confidence_label.setText(f"{avg_conf:.2f}")

        # Distribution text
        attack_summary = summary.get("attack_summary") or {}
        distribution_lines = []
        for label, count in attack_summary.items():
            if total_flows:
                percentage = (count / total_flows) * 100
            else:
                percentage = 0.0
            distribution_lines.append(f"{label}: {count} flows ({percentage:.1f}%)")
        self.distribution_text.setPlainText(
            "\n".join(distribution_lines) if distribution_lines else "No attack data available."
        )

        # Top attacks text
        top_attacks = summary.get("top_attacks") or []
        if top_attacks:
            lines = []
            for entry in top_attacks:
                attack_type = entry.get("attack_type", "Unknown")
                count = entry.get("count", 0)
                percentage = entry.get("percentage", 0.0)
                confidence = entry.get("avg_confidence")
                confidence_str = f"{confidence:.2f}" if isinstance(confidence, (int, float)) else "N/A"
                lines.append(
                    f"{attack_type}: {count} flows ({percentage:.1f}%) - Avg confidence {confidence_str}"
                )
            self.top_attacks_text.setPlainText("\n".join(lines))
        else:
            self.top_attacks_text.setPlainText("No top attack information provided.")

        # Detailed results table
        detailed_results = summary.get("detailed_results") or []
        max_rows = min(100, len(detailed_results))
        self.results_table.setRowCount(max_rows)

        for index in range(max_rows):
            record = detailed_results[index] or {}

            flow_id = (
                record.get("flow_id")
                or record.get("Flow ID")
                or str(index + 1)
            )
            src_ip = record.get("src_ip") or record.get("Source IP") or record.get("Src IP") or "N/A"
            dst_ip = record.get("dst_ip") or record.get("Destination IP") or record.get("Dest IP") or "N/A"
            label = record.get("Predicted_Label") or record.get("label") or record.get("Label") or "UNKNOWN"

            confidence_value = record.get("Confidence")
            if isinstance(confidence_value, str):
                try:
                    confidence_value = float(confidence_value)
                except ValueError:
                    confidence_value = None
            confidence_str = f"{confidence_value:.2f}" if isinstance(confidence_value, (int, float)) else "N/A"

            self.results_table.setItem(index, 0, QTableWidgetItem(str(flow_id)))
            self.results_table.setItem(index, 1, QTableWidgetItem(str(src_ip)))
            self.results_table.setItem(index, 2, QTableWidgetItem(str(dst_ip)))

            label_item = QTableWidgetItem(str(label))
            label_upper = str(label).upper()
            if label_upper == "BENIGN":
                label_item.setBackground(QColor("#d4edda"))
            elif "DOS" in label_upper:
                label_item.setBackground(QColor("#f8d7da"))
            elif "DDOS" in label_upper:
                label_item.setBackground(QColor("#f5c6cb"))
            elif "PORTSCAN" in label_upper or "SCAN" in label_upper:
                label_item.setBackground(QColor("#fff3cd"))
            else:
                label_item.setBackground(QColor("#e2e3e5"))
            self.results_table.setItem(index, 3, label_item)

            self.results_table.setItem(index, 4, QTableWidgetItem(confidence_str))

        self.export_btn.setEnabled(True)
        self.analyze_btn.setEnabled(True)

        # Force UI refresh to ensure all updates are visible
        self.update()
        self.repaint()

    def clear(self) -> None:
        """Clear all displayed results and reset the widget state."""
        self.results = None
        self._set_idle_state()

        self.total_flows_label.setText("0")
        self.attack_flows_label.setText("0")
        self.benign_flows_label.setText("0")
        self.avg_confidence_label.setText("0.00")

        self.distribution_text.clear()
        self.top_attacks_text.clear()
        self.results_table.setRowCount(0)
        self.analyze_btn.setEnabled(True)


