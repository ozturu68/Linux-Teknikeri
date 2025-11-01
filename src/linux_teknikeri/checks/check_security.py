"""
Sistem Güvenliği Analiz Modülü - API Gateway
=============================================

Güvenlik kontrollerini yapan ana modül giriş noktası.

Bu dosya geriye uyumluluk için mevcut API'yi export eder.
Gerçek implementasyon security/ modülündedir.

Public API:
    get_security_summary()           - Sistem güvenlik özeti
    get_listening_ports()            - Açık port tarama
    audit_ssh_config()               - SSH yapılandırma denetimi
    audit_multiple_ssh_configs()     - Çoklu SSH config denetimi
    check_failed_login_attempts()    - Başarısız giriş analizi
    
    SecuritySummary                  - Güvenlik özeti dataclass
    PortInfo                         - Port bilgisi dataclass
    SSHAudit                         - SSH denetim dataclass
    SecurityLevel                    - Güvenlik seviyesi enum
    SSHSecurityLevel                 - SSH güvenlik seviyesi enum

Modül Refactoring (v0.5.0):
    ❌ ÖNCE: check_security.py (2200+ satır, monolitik)
    ✅ SONRA: security/ modülü (11 dosya, modüler)
    
    Avantajlar:
        ✅ Bakım kolaylığı (küçük dosyalar)
        ✅ Test edilebilirlik (her modül ayrı)
        ✅ Yeniden kullanım (bağımsız modüller)
        ✅ Import hızı (lazy loading)
        ✅ Type checking hızı (mypy daha hızlı)
        ✅ Takım çalışması (conflict azalır)

Örnekler:
    >>> # Temel kullanım (değişmedi!)
    >>> from linux_teknikeri.checks.check_security import (
    ...     get_security_summary,
    ...     get_listening_ports,
    ...     audit_ssh_config
    ... )
    >>> 
    >>> # Güvenlik özeti
    >>> summary = get_security_summary()
    >>> print(f"Güvenlik skoru: {summary['security_updates_count']}")
    >>> 
    >>> # Port tarama
    >>> ports = get_listening_ports()
    >>> print(f"{len(ports)} port bulundu")
    >>> 
    >>> # SSH denetimi
    >>> ssh = audit_ssh_config()
    >>> print(f"SSH risk: {ssh['risk_level']}")

Migration Guide:
    Eski import'lar çalışmaya devam eder:
    
    # ✅ Hala çalışır
    from linux_teknikeri.checks.check_security import get_security_summary
    
    # ✅ Yeni (önerilen)
    from linux_teknikeri.checks.security import get_security_summary

Notlar:
    - Bu dosya geriye uyumluluk için korunmaktadır
    - Yeni özellikler security/ modülüne eklenir
    - API değişmez (backward compatible)

See Also:
    - security/__init__.py: Yeni modül giriş noktası
    - security/summary.py: Güvenlik özeti implementasyonu
    - security/ports.py: Port tarama implementasyonu
    - security/ssh/: SSH denetimi alt modülü

Author: ozturu68
Version: 0.5.0 (Refactored)
Date: 2025-11-01
License: MIT
"""

# Standard library
import logging
from typing import Dict, List, Optional, Any
from pathlib import Path

# Version
__version__ = '0.5.0'
__refactored__ = True  # Refactoring bayrağı

# Logger
log = logging.getLogger(__name__)


# =============================================================================
# SECURITY MODÜLÜNDEN IMPORT (TÜM PUBLIC API)
# =============================================================================

try:
    # Dataclass'lar (veri modelleri)
    from .security import (
        SecuritySummary,
        PortInfo,
        SSHAudit,
    )
    
    # Enum'lar (güvenlik seviyeleri)
    from .security import (
        SecurityLevel,
        SSHSecurityLevel,
    )
    
    # Ana fonksiyonlar
    from .security import (
        get_security_summary,
        get_listening_ports,
        audit_ssh_config,
        audit_multiple_ssh_configs,
        check_failed_login_attempts,
    )
    
    # Bonus: Tam rapor fonksiyonu (yeni!)
    from .security import (
        get_full_security_report,
    )
    
    log.debug(f"check_security module loaded (v{__version__}, refactored)")

except ImportError as e:
    log.error(
        f"Security modülü import edilemedi: {e}\n"
        f"security/ klasörünün varlığını kontrol edin!"
    )
    raise


# =============================================================================
# PUBLIC API (EXPORT)
# =============================================================================

__all__ = [
    # === DATACLASS'LAR ===
    'SecuritySummary',    # Sistem güvenlik özeti
    'PortInfo',           # Port bilgileri
    'SSHAudit',           # SSH denetim sonuçları
    
    # === ENUM'LAR ===
    'SecurityLevel',      # Genel güvenlik seviyesi
    'SSHSecurityLevel',   # SSH güvenlik seviyesi
    
    # === ANA FONKSİYONLAR ===
    'get_security_summary',          # Sistem güvenlik özeti
    'get_listening_ports',           # Açık port tarama
    'audit_ssh_config',              # SSH config denetimi
    'audit_multiple_ssh_configs',    # Çoklu SSH config denetimi
    'check_failed_login_attempts',   # Başarısız giriş analizi
    
    # === BONUS FONKSİYON (YENİ!) ===
    'get_full_security_report',      # Tam güvenlik raporu (tüm kontroller)
    
    # === METADATA ===
    '__version__',        # Modül versiyonu
    '__refactored__',     # Refactoring bayrağı
]


# =============================================================================
# BACKWARD COMPATIBILITY HELPERS (Opsiyonel)
# =============================================================================

def _check_old_imports() -> None:
    """
    Eski import pattern'leri kontrol eder ve uyarır.
    
    Bu fonksiyon development sırasında eski import'ları tespit eder.
    Production'da devre dışı bırakılabilir.
    
    Note:
        Sadece warning verir, kod çalışmaya devam eder.
    """
    import sys
    import warnings
    
    # Caller'ı tespit et
    frame = sys._getframe(2)
    caller_file = frame.f_code.co_filename
    caller_line = frame.f_lineno
    
    # check_security.py'den direkt import var mı?
    if 'check_security' in caller_file:
        return  # Kendimizden import, problem yok
    
    # Eski pattern tespit edildi
    warnings.warn(
        f"Eski import pattern tespit edildi: {caller_file}:{caller_line}\n"
        f"Önerilen: from linux_teknikeri.checks.security import ...\n"
        f"Mevcut kod çalışmaya devam edecek (backward compatible)",
        DeprecationWarning,
        stacklevel=3
    )


# =============================================================================
# MODULE METADATA
# =============================================================================

# Modül bilgileri
__author__ = 'ozturu68'
__email__ = 'ozturu68@example.com'
__license__ = 'MIT'
__status__ = 'Production'

# Versiyon bilgisi
__version_info__ = (0, 5, 0)
__version__ = '.'.join(map(str, __version_info__))

# Refactoring tarihi
__refactored_date__ = '2025-11-01'

log.info(
    f"check_security.py loaded (v{__version__}) - "
    f"Refactored architecture, {len(__all__)} exports"
)


# =============================================================================
# CONVENIENCE FUNCTIONS (Yardımcı fonksiyonlar - opsiyonel)
# =============================================================================

def get_module_info() -> Dict[str, Any]:
    """
    Modül bilgilerini döndürür (debug/info için).
    
    Returns:
        Dict[str, Any]: Modül metadata
    
    Examples:
        >>> info = get_module_info()
        >>> print(info['version'])
        0.5.0
        >>> print(info['refactored'])
        True
    """
    return {
        'version': __version__,
        'refactored': __refactored__,
        'refactored_date': __refactored_date__,
        'author': __author__,
        'exports': __all__,
        'export_count': len(__all__),
        'status': __status__,
    }


def print_migration_guide() -> None:
    """
    Migration guide'ı yazdırır (yardımcı fonksiyon).
    
    Eski import'lardan yeni import'lara geçiş rehberi.
    
    Examples:
        >>> print_migration_guide()
        Migration Guide - check_security.py Refactoring
        ================================================
        ...
    """
    guide = """
Migration Guide - check_security.py Refactoring
================================================

Modül refactor edildi! (v0.5.0 - 2025-11-01)

ÖNCE: Monolitik yapı (2200+ satır)
SONRA: Modüler yapı (11 dosya, ~6000+ satır)

✅ ESKİ İMPORT'LAR ÇALIŞMAYA DEVAM EDER!

Eski Kullanım (hala çalışır):
    from linux_teknikeri.checks.check_security import (
        get_security_summary,
        get_listening_ports,
        audit_ssh_config
    )

Yeni Kullanım (önerilen):
    from linux_teknikeri.checks.security import (
        get_security_summary,
        get_listening_ports,
        audit_ssh_config
    )

Avantajlar:
    ✅ Daha hızlı import
    ✅ Daha iyi modüler yapı
    ✅ Daha kolay test
    ✅ Lazy loading desteği

Yeni Özellikler:
    • get_full_security_report()  - Tüm kontrolleri tek seferde
    • SecuritySummary.get_security_score()  - Skor hesaplama
    • SSHAudit.get_security_score()  - SSH skoru
    • PortInfo.get_security_risk()  - Port risk analizi
    • Daha fazla helper fonksiyon

Daha Fazla Bilgi:
    security/__init__.py
    security/README.md (varsa)
    
================================================
    """
    print(guide)


# =============================================================================
# ÖRNEK KULLANIM (bu dosya çalıştırılırsa)
# =============================================================================

if __name__ == "__main__":
    """
    check_security.py doğrudan çalıştırılırsa örnek kullanım göster.
    """
    import json
    
    print("=" * 70)
    print("check_security.py - API Gateway (Refactored v0.5.0)")
    print("=" * 70)
    print()
    
    # Modül bilgisi
    print("📦 Modül Bilgisi:")
    info = get_module_info()
    print(json.dumps(info, indent=2, ensure_ascii=False))
    print()
    
    # Migration guide
    print("📚 Migration Guide:")
    print_migration_guide()
    print()
    
    # Test: Fonksiyonlar import edilebiliyor mu?
    print("✅ Import Testi:")
    try:
        # Fonksiyonları test et
        assert callable(get_security_summary)
        assert callable(get_listening_ports)
        assert callable(audit_ssh_config)
        assert callable(check_failed_login_attempts)
        print("  ✅ get_security_summary: OK")
        print("  ✅ get_listening_ports: OK")
        print("  ✅ audit_ssh_config: OK")
        print("  ✅ check_failed_login_attempts: OK")
        
        # Dataclass'ları test et
        assert SecuritySummary is not None
        assert PortInfo is not None
        assert SSHAudit is not None
        print("  ✅ SecuritySummary: OK")
        print("  ✅ PortInfo: OK")
        print("  ✅ SSHAudit: OK")
        
        # Enum'ları test et
        assert SecurityLevel is not None
        assert SSHSecurityLevel is not None
        print("  ✅ SecurityLevel: OK")
        print("  ✅ SSHSecurityLevel: OK")
        
        print()
        print("🎉 Tüm import'lar başarılı!")
        print()
        
    except Exception as e:
        print(f"❌ Import hatası: {e}")
        import traceback
        traceback.print_exc()
    
    # Örnek kullanım
    print("📋 Örnek Kullanım:")
    print()
    print("  from linux_teknikeri.checks.security import (")
    print("      get_security_summary,")
    print("      get_listening_ports,")
    print("      audit_ssh_config")
    print("  )")
    print()
    print("  # Güvenlik özeti")
    print("  summary = get_security_summary()")
    print("  print(f'Güvenlik güncellemesi: {summary[\"security_updates_count\"]}')")
    print()
    print("  # Port tarama")
    print("  ports = get_listening_ports()")
    print("  print(f'{len(ports)} port bulundu')")
    print()
    print("  # SSH denetimi")
    print("  ssh = audit_ssh_config()")
    print("  print(f'SSH risk: {ssh[\"risk_level\"]}')")
    print()
    
    print("=" * 70)