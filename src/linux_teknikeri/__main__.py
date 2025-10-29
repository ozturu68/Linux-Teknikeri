"""
Linux Teknikeri - Main Entry Point
==================================

Python modülü olarak çalıştırma için entry point.

Kullanım:
    python -m linux_teknikeri
    python -m linux_teknikeri --help
    python -m linux_teknikeri --html rapor.html

Author: ozturu68
"""

import sys

if __name__ == "__main__":
    from linux_teknikeri.main import main
    sys.exit(main())
