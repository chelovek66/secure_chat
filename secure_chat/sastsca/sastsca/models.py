"""
Модели данных для находок SAST и SCA, уровней критичности и отчетов.
"""

from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_str(cls, val: str) -> "Severity":
        val_clean = (val or "").strip().lower()
        if val_clean in ("crit", "critical"):
            return cls.CRITICAL
        if val_clean in ("high", "h"):
            return cls.HIGH
        if val_clean in ("med", "medium", "moderate"):
            return cls.MEDIUM
        return cls.LOW

    def rank(self) -> int:
        order = {
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        return order[self]

    def __ge__(self, other: "Severity") -> bool:
        return self.rank() >= other.rank()

    def __gt__(self, other: "Severity") -> bool:
        return self.rank() > other.rank()


class Finding(BaseModel):
    """Единая структура находки уязвимости (SAST или SCA)."""
    category: str = Field(..., description="'SAST' или 'SCA'")
    rule_id: str = Field(..., description="Идентификатор правила (SAST-xxx или CVE-xxx)")
    title: str = Field(..., description="Краткое описание уязвимости")
    severity: str = Field(..., description="Уровень критичности (low, medium, high, critical)")
    file_path: str = Field(..., description="Относительный путь к файлу")
    line: Optional[int] = Field(None, description="Номер строки (для SAST)")
    column: Optional[int] = Field(None, description="Номер столбца (для SAST)")
    snippet: Optional[str] = Field(None, description="Фрагмент опасного кода или строки манифеста")
    cwe: Optional[str] = Field(None, description="Идентификатор CWE (например, CWE-798)")
    cve: Optional[str] = Field(None, description="Идентификатор CVE/OSV (для SCA)")
    package_name: Optional[str] = Field(None, description="Имя пакета/библиотеки (для SCA)")
    installed_version: Optional[str] = Field(None, description="Текущая версия зависимости (для SCA)")
    fixed_version: Optional[str] = Field(None, description="Рекомендуемая безопасная версия (для SCA)")
    remediation: Optional[str] = Field(None, description="Рекомендация по исправлению")


class ScanSummary(BaseModel):
    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    sast_count: int = 0
    sca_count: int = 0
    scanned_files_count: int = 0
    scanned_dependencies_count: int = 0


class ScanReport(BaseModel):
    scanner: str = "sastsca v1.0.0"
    target_path: str
    scan_timestamp: str
    summary: ScanSummary
    findings: List[Finding] = Field(default_factory=list)
