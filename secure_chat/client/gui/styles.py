"""
Стилизация графического интерфейса PyQt5 (QSS).
Современная эргономичная темная тема с акцентами по стандартам десктопных приложений.
"""

APP_STYLESHEET = """
QWidget {
    background-color: #2B2D30;
    color: #F8FAFC;
    font-family: "Segoe UI", "Arial", sans-serif;
    font-size: 13px;
}

QMainWindow, QDialog {
    background-color: #2B2D30;
}

QLabel {
    color: #E2E8F0;
}

QLabel#titleLabel {
    font-size: 17px;
    font-weight: bold;
    color: #E2E8F0;
}

QLabel#subtitleLabel {
    color: #9DA5B0;
    font-size: 12px;
}

QLineEdit {
    background-color: #3C3F41;
    border: 1px solid #4E5254;
    border-radius: 6px;
    padding: 7px 12px;
    color: #FFFFFF;
    selection-background-color: #5A606A;
}

QLineEdit:focus {
    border: 1px solid #9CA3AF;
    background-color: #3C3F41;
}

QPushButton {
    background-color: #5A606A;
    color: #FFFFFF;
    border: none;
    border-radius: 6px;
    padding: 8px 16px;
    font-weight: 600;
}

QPushButton:hover {
    background-color: #6B7280;
}

QPushButton:pressed {
    background-color: #4B515B;
}

QPushButton:disabled {
    background-color: #4E5254;
    color: #868D96;
}

QPushButton#secondaryButton {
    background-color: #4E5254;
    color: #F8FAFC;
    border: 1px solid #5E646A;
}

QPushButton#secondaryButton:hover {
    background-color: #5E646A;
}

QPushButton#successButton {
    background-color: #059669;
}

QPushButton#successButton:hover {
    background-color: #047857;
}

QTextEdit {
    background-color: #1E1F22;
    border: 1px solid #3C3F41;
    border-radius: 8px;
    padding: 10px;
    color: #E2E8F0;
    selection-background-color: #9CA3AF;
}

QListWidget {
    background-color: #3C3F41;
    border: 1px solid #4E5254;
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
    background-color: #4E5254;
}

QListWidget::item:selected {
    background-color: #5A606A;
    color: #FFFFFF;
}

QScrollBar:vertical {
    border: none;
    background: #2B2D30;
    width: 8px;
    margin: 0px;
}

QScrollBar::handle:vertical {
    background: #4E5254;
    min-height: 20px;
    border-radius: 4px;
}

QScrollBar::handle:vertical:hover {
    background: #5E646A;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

QScrollBar:horizontal {
    border: none;
    background: #2B2D30;
    height: 8px;
    margin: 0px;
}

QScrollBar::handle:horizontal {
    background: #4E5254;
    min-width: 20px;
    border-radius: 4px;
}

QScrollBar::handle:horizontal:hover {
    background: #5E646A;
}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0px;
}

QStatusBar {
    background-color: #1E1F22;
    color: #9DA5B0;
    border-top: 1px solid #3C3F41;
}

QTabWidget::pane {
    border: 1px solid #4E5254;
    background-color: #3C3F41;
    border-radius: 6px;
    top: -1px;
}

QTabBar::tab {
    background-color: #2B2D30;
    color: #9DA5B0;
    border: 1px solid #4E5254;
    border-bottom: none;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    padding: 8px 16px;
    margin-right: 4px;
    font-weight: 500;
}

QTabBar::tab:selected {
    background-color: #3C3F41;
    color: #E2E8F0;
    border-color: #9CA3AF;
    border-bottom: 2px solid #9CA3AF;
    font-weight: 600;
}

QTabBar::tab:hover:!selected {
    background-color: #3C3F41;
    color: #F8FAFC;
}

QTableWidget, QTableView {
    background-color: #1E1F22;
    alternate-background-color: #323538;
    border: 1px solid #4E5254;
    border-radius: 6px;
    gridline-color: #3C3F41;
    color: #F8FAFC;
    selection-background-color: #5A606A;
    selection-color: #FFFFFF;
}

QTableWidget::item, QTableView::item {
    padding: 6px 10px;
    border-bottom: 1px solid #3C3F41;
    color: #F1F5F9;
}

QTableWidget::item:selected, QTableView::item:selected {
    background-color: #6B7280;
    color: #FFFFFF;
}

QTableCornerButton::section, QTableView QTableCornerButton::section {
    background-color: #3C3F41;
    border: none;
    border-bottom: 1px solid #4E5254;
    border-right: 1px solid #4E5254;
}

QHeaderView {
    background-color: #3C3F41;
}

QHeaderView::section {
    background-color: #3C3F41;
    color: #9DA5B0;
    padding: 6px 10px;
    border: none;
    border-bottom: 1px solid #4E5254;
    border-right: 1px solid #4E5254;
    font-weight: 600;
    font-size: 12px;
}

QComboBox {
    background-color: #3C3F41;
    border: 1px solid #4E5254;
    border-radius: 6px;
    padding: 5px 12px;
    color: #FFFFFF;
    min-height: 20px;
}

QComboBox:hover {
    border-color: #9CA3AF;
}

QComboBox::drop-down {
    border: none;
    width: 24px;
}

QComboBox::down-arrow {
    image: none;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 5px solid #9DA5B0;
    width: 0;
    height: 0;
    margin-right: 8px;
}

QComboBox QAbstractItemView {
    background-color: #3C3F41;
    border: 1px solid #4E5254;
    selection-background-color: #5A606A;
    selection-color: #FFFFFF;
    color: #F8FAFC;
    padding: 4px;
}

QGroupBox {
    border: 1px solid #4E5254;
    border-radius: 6px;
    margin-top: 14px;
    padding-top: 12px;
    font-weight: 600;
    color: #CBD5E1;
}

QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 10px;
    padding: 0 4px;
}

QSpinBox, QDoubleSpinBox {
    background-color: #3C3F41;
    border: 1px solid #4E5254;
    border-radius: 6px;
    padding: 5px 8px;
    color: #FFFFFF;
}

QSpinBox:focus, QDoubleSpinBox:focus {
    border-color: #9CA3AF;
}

QCheckBox {
    color: #E2E8F0;
    spacing: 8px;
}

QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border: 1px solid #5E646A;
    border-radius: 4px;
    background-color: #3C3F41;
}

QCheckBox::indicator:checked {
    background-color: #5A606A;
    border-color: #9CA3AF;
}
"""
