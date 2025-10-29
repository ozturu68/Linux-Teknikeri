"""
Linux Teknikeri - Raporlama Modülleri
=====================================

HTML, JSON, PDF ve diğer formatlarda rapor üretimi.

Modules:
    - html_reporter: Modern, interaktif HTML raporları
    - json_reporter: (Planlı) JSON export
    - pdf_reporter: (Planlı) PDF export

Features:
    - Bootstrap 5 ve Chart.js ile modern HTML
    - Responsive tasarım (mobil uyumlu)
    - Dark mode desteği
    - Print-friendly (PDF export için)
    - Interaktif grafikler ve tablolar

Author: ozturu68
Version: 0.4.0
Date: 2025-01-29
"""

__version__ = "0.4.0"

__all__ = [
    'generate_html_report',
    'get_available_formats',
    'get_reporting_info',
]

import logging

log = logging.getLogger(__name__)

# HTML Reporter'ı import et
try:
    from .html_reporter import generate_html_report
    log.debug("HTML reporter modülü yüklendi")
    HTML_REPORTER_AVAILABLE = True
except ImportError as e:
    log.warning(f"HTML reporter yüklenemedi: {e}")
    HTML_REPORTER_AVAILABLE = False
    
    # Fallback fonksiyon
    def generate_html_report(*args, **kwargs):
        """Fallback HTML reporter - modül yüklenemediğinde."""
        raise ImportError(
            "HTML reporter modülü yüklenemedi. "
            "html_reporter.py dosyasının varlığını kontrol edin."
        )


def get_available_formats():
    """
    Mevcut rapor formatlarını döndürür.
    
    Returns:
        list: Format listesi
        
    Examples:
        >>> formats = get_available_formats()
        >>> 'html' in formats
        True
    """
    formats = []
    
    if HTML_REPORTER_AVAILABLE:
        formats.append('html')
    
    # Gelecekte eklenecek
    # if JSON_REPORTER_AVAILABLE:
    #     formats.append('json')
    
    return formats


def get_reporting_info():
    """
    Raporlama modülü bilgilerini döndürür.
    
    Returns:
        dict: Modül bilgileri
        
    Examples:
        >>> info = get_reporting_info()
        >>> info['version']
        '0.4.0'
    """
    return {
        'module': 'linux_teknikeri.reporting',
        'version': __version__,
        'status': 'active',
        'available_formats': get_available_formats(),
        'html_reporter': HTML_REPORTER_AVAILABLE,
        'features': [
            'Modern HTML raporları',
            'Bootstrap 5 tasarım',
            'Chart.js grafikler',
            'Responsive layout',
            'Print-friendly'
        ]
    }


def check_module_health():
    """
    Reporting modülünün sağlık durumunu kontrol eder.
    
    Returns:
        dict: Durum bilgisi
    """
    issues = []
    
    if not HTML_REPORTER_AVAILABLE:
        issues.append("HTML reporter modülü yüklenemedi")
    
    return {
        'healthy': len(issues) == 0,
        'issues': issues,
        'available_reporters': get_available_formats()
    }


# Module yüklendiğinde sağlık kontrolü yap
_health = check_module_health()
if not _health['healthy']:
    for issue in _health['issues']:
        log.warning(f"Reporting modülü uyarısı: {issue}")
else:
    log.info(f"Reporting modülü hazır: {_health['available_reporters']}")