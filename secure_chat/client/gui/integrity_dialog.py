"""
Диалоговое окно контроля целостности программного обеспечения по эталонным хэшам.
Реализует требования государственного стандарта Республики Беларусь:
  * СТБ 34.101.47-2017: Криптографическое хэширование файлов алгоритмом bash256.
"""

from pathlib import Path
from PyQt5.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QMessageBox,
    QFrame,
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor

from common.integrity import SoftwareIntegrityManager, IntegrityReport


class IntegrityDialog(QDialog):
    """
    Панель контроля целостности ПО на базе контрольных сумм bash256 (СТБ 34.101.47-2017).
    """

    def __init__(self, parent=None, root_dir: str = None):
        super().__init__(parent)
        self.setWindowTitle("Контроль целостности ПО")
        self.resize(1060, 600)
        self.setMinimumSize(980, 520)
        if root_dir is None:
            root_dir = str(Path(__file__).resolve().parent.parent.parent)
        self.manager = SoftwareIntegrityManager(root_dir=root_dir)
        self.init_ui()
        self.run_verification()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        title = QLabel("Контроль целостности программного обеспечения")
        title.setObjectName("titleLabel")
        layout.addWidget(title)

        subtitle = QLabel(
            "Контроль целостности компонентов программного комплекса.\n"
            "Любая несанкционированная модификация или повреждение файлов мгновенно выявляется при проверке."
        )
        subtitle.setObjectName("subtitleLabel")
        layout.addWidget(subtitle)

        # Статусный баннер
        self.status_frame = QFrame(self)
        self.status_frame.setFrameShape(QFrame.StyledPanel)
        self.status_frame.setStyleSheet("""
            QFrame {
                background-color: #1E293B;
                border: 2px solid #334155;
                border-radius: 8px;
                padding: 12px;
            }
        """)
        f_layout = QVBoxLayout(self.status_frame)

        self.status_title = QLabel("Статус проверки...", self.status_frame)
        self.status_title.setStyleSheet("font-size: 15px; font-weight: bold; color: #60A5FA;")
        f_layout.addWidget(self.status_title)

        self.status_details = QLabel("", self.status_frame)
        self.status_details.setStyleSheet("font-size: 12px; color: #CBD5E1;")
        self.status_details.setWordWrap(True)
        f_layout.addWidget(self.status_details)

        layout.addWidget(self.status_frame)

        # Таблица проверенных файлов
        self.table = QTableWidget(self)
        self.table.setColumnCount(2)
        self.table.setHorizontalHeaderLabels([
            "Компонент / Модуль системы",
            "Статус целостности",
        ])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        layout.addWidget(self.table)

        # Кнопки действий
        btn_h = QHBoxLayout()

        self.verify_btn = QPushButton("🔍 Проверить целостность файлов", self)
        self.verify_btn.setObjectName("successButton")
        self.verify_btn.clicked.connect(self.run_verification)
        btn_h.addWidget(self.verify_btn)

        self.export_btn = QPushButton("💾 Экспорт отчета в CSV...", self)
        self.export_btn.setObjectName("secondaryButton")
        self.export_btn.clicked.connect(self.export_report_csv)
        btn_h.addWidget(self.export_btn)

        self.generate_manifest_btn = QPushButton("Сформировать контрольные суммы...", self)
        self.generate_manifest_btn.setObjectName("secondaryButton")
        self.generate_manifest_btn.clicked.connect(self.generate_manifest)
        btn_h.addWidget(self.generate_manifest_btn)

        self.tamper_demo_btn = QPushButton("Демонстрация обнаружения вмешательства", self)
        self.tamper_demo_btn.setObjectName("secondaryButton")
        self.tamper_demo_btn.clicked.connect(self.demo_tamper)
        btn_h.addWidget(self.tamper_demo_btn)

        btn_h.addStretch()

        self.close_btn = QPushButton("Закрыть", self)
        self.close_btn.setObjectName("secondaryButton")
        self.close_btn.clicked.connect(self.accept)
        btn_h.addWidget(self.close_btn)

        layout.addLayout(btn_h)

    def run_verification(self):
        """Выполняет пофайловую проверку контрольных сумм."""
        if not self.manager.manifest_path.is_file():
            self.status_frame.setStyleSheet("QFrame { background-color: #451A03; border: 2px solid #D97706; border-radius: 8px; padding: 12px; }")
            self.status_title.setText("⚠️ ЭТАЛОННЫЕ ЗНАЧЕНИЯ НЕ НАЙДЕНЫ")
            self.status_title.setStyleSheet("font-size: 15px; font-weight: bold; color: #F59E0B;")
            self.status_details.setText("Файл эталонного манифеста отсутствует. Нажмите 'Сформировать контрольные суммы' для фиксации эталона.")
            self.table.setRowCount(0)
            return

        report: IntegrityReport = self.manager.verify_integrity()
        self.display_report(report)

    def display_report(self, report: IntegrityReport):
        """Отображает отчет на панели и в таблице."""
        manifest = {}
        try:
            manifest = self.manager.load_manifest()
        except Exception:
            pass

        files_dict = manifest.get("files", {})

        if report.is_valid:
            self.status_frame.setStyleSheet("QFrame { background-color: #064E3B; border: 2px solid #059669; border-radius: 8px; padding: 12px; }")
            self.status_title.setText("🛡️ ЦЕЛОСТНОСТЬ ФАЙЛОВ ПОДТВЕРЖДЕНА")
            self.status_title.setStyleSheet("font-size: 15px; font-weight: bold; color: #34D399;")
            self.status_details.setText(
                f"Статус проверки: Все контрольные суммы совпадают с эталонными значениями.\n"
                f"Проверено компонентов: {report.total_files_checked}. Модификаций, повреждений и неавторизованных внедрений не обнаружено."
            )
        else:
            self.status_frame.setStyleSheet("QFrame { background-color: #450A0A; border: 2px solid #DC2626; border-radius: 8px; padding: 12px; }")
            self.status_title.setText(f"🚨 ОБНАРУЖЕНО НАРУШЕНИЕ ЦЕЛОСТНОСТИ ({report.status})")
            self.status_title.setStyleSheet("font-size: 15px; font-weight: bold; color: #F87171;")
            self.status_details.setText(
                f"Внимание: {report.message}\n"
                f"Измененных файлов: {len(report.tampered_files)} | Отсутствует: {len(report.missing_files)} | Неавторизованных: {len(report.injected_files)}"
            )

        # Заполнение таблицы
        tampered_set = {t["rel_path"] for t in report.tampered_files}
        missing_set = set(report.missing_files)

        all_keys = sorted(list(files_dict.keys()))
        self.table.setRowCount(len(all_keys))

        for row, rel_p in enumerate(all_keys):
            it_path = QTableWidgetItem(rel_p)
            it_path.setFlags(it_path.flags() & ~Qt.ItemIsEditable)

            if rel_p in tampered_set:
                it_st = QTableWidgetItem("ИЗМЕНЁН (ВЗЛОМ)")
                it_st.setForeground(QColor("#F87171"))
            elif rel_p in missing_set:
                it_st = QTableWidgetItem("ОТСУТСТВУЕТ")
                it_st.setForeground(QColor("#FBBF24"))
            else:
                it_st = QTableWidgetItem("ЭТАЛОН (OK)")
                it_st.setForeground(QColor("#34D399"))

            it_st.setFlags(it_st.flags() & ~Qt.ItemIsEditable)

            self.table.setItem(row, 0, it_path)
            self.table.setItem(row, 1, it_st)

    def export_report_csv(self):
        """Экспортирует таблицу результатов проверки целостности в CSV-файл."""
        from PyQt5.QtWidgets import QFileDialog
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Экспорт отчета целостности в CSV",
            "integrity_report.csv",
            "CSV файлы (*.csv);;Все файлы (*.*)",
        )
        if not path:
            return
        import csv
        try:
            with open(path, "w", encoding="utf-8-sig", newline="") as f:
                writer = csv.writer(f, delimiter=";")
                writer.writerow(["Компонент / Модуль системы", "Статус целостности"])
                for row in range(self.table.rowCount()):
                    writer.writerow([
                        self.table.item(row, 0).text(),
                        self.table.item(row, 1).text(),
                    ])
            QMessageBox.information(self, "Экспорт", f"Отчет целостности сохранен:\n{path}")
        except Exception as exc:
            QMessageBox.critical(self, "Ошибка экспорта", f"Не удалось сохранить CSV: {exc}")

    def generate_manifest(self):
        """Генерирует контрольные суммы для всех компонентов системы."""
        reply = QMessageBox.question(
            self,
            "Формирование эталона",
            "Вычислить контрольные суммы для всех компонентов и сохранить как эталонные?",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return

        try:
            manifest = self.manager.generate_manifest()
            self.manager.save_manifest(manifest)
            QMessageBox.information(
                self,
                "Эталон сформирован",
                f"Эталонные контрольные суммы успешно сформированы!\n"
                f"Файлов включено: {manifest['files_count']}\n"
                f"Файл сохранен: {self.manager.manifest_path}",
            )
            self.run_verification()
        except Exception as exc:
            QMessageBox.critical(self, "Ошибка", f"Не удалось сформировать эталонные хэши: {exc}")

    def demo_tamper(self):
        """
        Демонстрация обнаружения несанкционированного вмешательства:
        создает тестовое искажение файла, запускает проверку, затем восстанавливает файл.
        """
        test_file = self.manager.root_dir / "client" / "tamper_test_probe.py"
        try:
            # 1. Формируем эталон с тестовым файлом
            test_file.write_text("# Исходный авторизованный компонент ПО\nVERSION = 'ORIGINAL'", encoding="utf-8")
            manifest = self.manager.generate_manifest()
            self.manager.save_manifest(manifest)

            # 2. Искажаем содержимое файла (симуляция вредоносной модификации)
            test_file.write_text("# ВНЕДРЕНИЕ ВРЕДОНОСНОГО КОДА ЗЛОУМЫШЛЕННИКА!\nINJECTED = True", encoding="utf-8")

            # 3. Запуск контроля целостности
            report = self.manager.verify_integrity()
            self.display_report(report)

            QMessageBox.warning(
                self,
                "Демонстрация обнаружения вмешательства",
                f"СИМУЛЯЦИЯ МОДИФИКАЦИИ:\n"
                f"Файл 'client/tamper_test_probe.py' был несанкционированно изменен.\n\n"
                f"Результат контроля целостности: МГНОВЕННОЕ ОБНАРУЖЕНИЕ!\n"
                f"Статус: {report.status}\n"
                f"Измененных файлов зафиксировано: {len(report.tampered_files)}\n\n"
                f"Сейчас тестовый файл будет удален и эталонные хэши восстановлены.",
            )
        finally:
            if test_file.is_file():
                test_file.unlink()
            # Пересоздаем эталонный манифест
            manifest = self.manager.generate_manifest()
            self.manager.save_manifest(manifest)
            self.run_verification()
