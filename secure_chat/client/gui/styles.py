"""
Стилизация графического интерфейса PyQt5 (QSS).
Современная эргономичная темная тема с акцентами по стандартам десктопных приложений.
"""

APP_STYLESHEET = """
QWidget {
    background-color: #0F172A;
    color: #F8FAFC;
    font-family: "Segoe UI", "Arial", sans-serif;
    font-size: 13px;
}

QMainWindow, QDialog {
    background-color: #0F172A;
}

QLabel {
    color: #E2E8F0;
}

QLabel#titleLabel {
    font-size: 17px;
    font-weight: bold;
    color: #60A5FA;
}

QLabel#subtitleLabel {
    color: #94A3B8;
    font-size: 12px;
}

QLineEdit {
    background-color: #1E293B;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 7px 12px;
    color: #FFFFFF;
    selection-background-color: #2563EB;
}

QLineEdit:focus {
    border: 1px solid #3B82F6;
    background-color: #1E293B;
}

QPushButton {
    background-color: #2563EB;
    color: #FFFFFF;
    border: none;
    border-radius: 6px;
    padding: 8px 16px;
    font-weight: 600;
}

QPushButton:hover {
    background-color: #1D4ED8;
}

QPushButton:pressed {
    background-color: #1E40AF;
}

QPushButton:disabled {
    background-color: #334155;
    color: #64748B;
}

QPushButton#secondaryButton {
    background-color: #334155;
    color: #F8FAFC;
    border: 1px solid #475569;
}

QPushButton#secondaryButton:hover {
    background-color: #475569;
}

QPushButton#successButton {
    background-color: #059669;
}

QPushButton#successButton:hover {
    background-color: #047857;
}

QTextEdit {
    background-color: #0B1120;
    border: 1px solid #1E293B;
    border-radius: 8px;
    padding: 10px;
    color: #E2E8F0;
    selection-background-color: #3B82F6;
}

QListWidget {
    background-color: #1E293B;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 6px;
    color: #F8FAFC;
}

QListWidget::item {
    padding: 8px 10px;
    border-radius: 4px;
    margin-bottom: 2px;
}

QListWidget::item:hover {
    background-color: #334155;
}

QListWidget::item:selected {
    background-color: #2563EB;
    color: #FFFFFF;
}

QScrollBar:vertical {
    border: none;
    background: #0F172A;
    width: 8px;
    margin: 0px;
}

QScrollBar::handle:vertical {
    background: #334155;
    min-height: 20px;
    border-radius: 4px;
}

QScrollBar::handle:vertical:hover {
    background: #475569;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

QScrollBar:horizontal {
    border: none;
    background: #0F172A;
    height: 8px;
    margin: 0px;
}

QScrollBar::handle:horizontal {
    background: #334155;
    min-width: 20px;
    border-radius: 4px;
}

QScrollBar::handle:horizontal:hover {
    background: #475569;
}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0px;
}

QStatusBar {
    background-color: #0B1120;
    color: #94A3B8;
    border-top: 1px solid #1E293B;
}

QTabWidget::pane {
    border: 1px solid #334155;
    background-color: #1E293B;
    border-radius: 6px;
    top: -1px;
}

QTabBar::tab {
    background-color: #0F172A;
    color: #94A3B8;
    border: 1px solid #334155;
    border-bottom: none;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    padding: 8px 16px;
    margin-right: 4px;
    font-weight: 500;
}

QTabBar::tab:selected {
    background-color: #1E293B;
    color: #60A5FA;
    border-color: #3B82F6;
    border-bottom: 2px solid #3B82F6;
    font-weight: 600;
}

QTabBar::tab:hover:!selected {
    background-color: #1E293B;
    color: #F8FAFC;
}

QTableWidget, QTableView {
    background-color: #0B1120;
    alternate-background-color: #151F32;
    border: 1px solid #334155;
    border-radius: 6px;
    gridline-color: #1E293B;
    color: #F8FAFC;
    selection-background-color: #2563EB;
    selection-color: #FFFFFF;
}

QTableWidget::item, QTableView::item {
    padding: 6px 10px;
    border-bottom: 1px solid #1E293B;
    color: #F1F5F9;
}

QTableWidget::item:selected, QTableView::item:selected {
    background-color: #1D4ED8;
    color: #FFFFFF;
}

QTableCornerButton::section, QTableView QTableCornerButton::section {
    background-color: #1E293B;
    border: none;
    border-bottom: 1px solid #334155;
    border-right: 1px solid #334155;
}

QHeaderView {
    background-color: #1E293B;
}

QHeaderView::section {
    background-color: #1E293B;
    color: #94A3B8;
    padding: 6px 10px;
    border: none;
    border-bottom: 1px solid #334155;
    border-right: 1px solid #334155;
    font-weight: 600;
    font-size: 12px;
}

QComboBox {
    background-color: #1E293B;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 5px 12px;
    color: #FFFFFF;
    min-height: 20px;
}

QComboBox:hover {
    border-color: #3B82F6;
}

QComboBox::drop-down {
    border: none;
    width: 24px;
}

QComboBox::down-arrow {
    image: none;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 5px solid #94A3B8;
    width: 0;
    height: 0;
    margin-right: 8px;
}

QComboBox QAbstractItemView {
    background-color: #1E293B;
    border: 1px solid #334155;
    selection-background-color: #2563EB;
    selection-color: #FFFFFF;
    color: #F8FAFC;
    padding: 4px;
}

QGroupBox {
    border: 1px solid #334155;
    border-radius: 6px;
    margin-top: 14px;
    padding-top: 12px;
    font-weight: 600;
    color: #93C5FD;
}

QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 10px;
    padding: 0 4px;
}

QSpinBox, QDoubleSpinBox {
    background-color: #1E293B;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 5px 8px;
    color: #FFFFFF;
}

QSpinBox:focus, QDoubleSpinBox:focus {
    border-color: #3B82F6;
}

QCheckBox {
    color: #E2E8F0;
    spacing: 8px;
}

QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border: 1px solid #475569;
    border-radius: 4px;
    background-color: #1E293B;
}

QCheckBox::indicator:checked {
    background-color: #2563EB;
    border-color: #3B82F6;
}
"""
