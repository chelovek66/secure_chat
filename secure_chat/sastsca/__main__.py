import sys
from pathlib import Path

# Добавляем родительский каталог пакета в sys.path для прозрачного запуска
PACKAGE_ROOT = Path(__file__).resolve().parent / "sastsca"
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))
PARENT_ROOT = Path(__file__).resolve().parent
if str(PARENT_ROOT) not in sys.path:
    sys.path.insert(0, str(PARENT_ROOT))

from sastsca.sastsca.cli import main

if __name__ == "__main__":
    sys.exit(main())
