"""
Linux Teknikeri - Kapsamlı Sistem Analizi ve Raporlama Aracı
=============================================================

Pop!_OS, Ubuntu ve Debian tabanlı sistemler için geliştirilmiş
profesyonel sistem bakım ve analiz aracı.

Features:
    - Sistem envanteri ve donanım bilgileri
    - S.M.A.R.T. disk sağlık kontrolü
    - GPU sürücü analizi
    - Güvenlik denetimi (firewall, SSH, failed logins)
    - Servis sağlık analizi
    - Performans metrikleri
    - Açılış performans analizi
    - HTML ve JSON rapor export

Author: ozturu68
License: MIT
Python: >=3.8
Date: 2025-10-29
"""

__version__ = "0.4.0"
__author__ = "ozturu68"
__email__ = "ozturu68@users.noreply.github.com"
__license__ = "MIT"
__url__ = "https://github.com/ozturu68/Linux-Teknikeri"
__description__ = "Pop!_OS ve Debian tabanlı sistemler için kapsamlı sistem analiz ve bakım aracı"

# Version tuple for programmatic access
VERSION = tuple(map(int, __version__.split('.')))

# Package metadata
__all__ = [
    '__version__',
    '__author__',
    '__license__',
    '__url__',
    'main',
    'VERSION'
]

# Ana program fonksiyonunu import et
from .main import main

# Versiyon kontrolü
import sys

if sys.version_info < (3, 8):
    raise RuntimeError(
        f"Linux Teknikeri requires Python 3.8 or higher. "
        f"You are using Python {sys.version_info.major}.{sys.version_info.minor}."
    )

# Bağımlılık kontrolü
def check_dependencies():
    """
    Kritik bağımlılıkların yüklü olup olmadığını kontrol eder.
    
    Returns:
        Tuple[bool, List[str]]: (tümü_yüklü, eksik_paketler)
    """
    required_packages = {
        'rich': 'rich',
        'psutil': 'psutil'
    }
    
    missing = []
    
    for import_name, package_name in required_packages.items():
        try:
            __import__(import_name)
        except ImportError:
            missing.append(package_name)
    
    return len(missing) == 0, missing


def get_version_info():
    """
    Detaylı versiyon bilgisini döndürür.
    
    Returns:
        dict: Versiyon bilgileri
    """
    all_ok, missing = check_dependencies()
    
    return {
        'version': __version__,
        'version_tuple': VERSION,
        'python_version': f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        'dependencies_ok': all_ok,
        'missing_dependencies': missing
    }


# Geliştiriciler için yardımcı bilgi
def _print_dev_info():
    """Geliştirici bilgilendirmesi (sadece debug modda)."""
    import os
    if os.environ.get('LINUX_TEKNIKERI_DEBUG'):
        print(f"[DEBUG] Linux Teknikeri v{__version__} yüklendi")
        print(f"[DEBUG] Python {sys.version}")
        all_ok, missing = check_dependencies()
        if not all_ok:
            print(f"[DEBUG] Eksik bağımlılıklar: {missing}")


# Module load sırasında kontrol
_print_dev_info()