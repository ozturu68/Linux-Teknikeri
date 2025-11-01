"""
Güvenlik Analiz Modülü
======================

Linux sistem güvenliği kontrollerini yapan kapsamlı modül.
Güvenlik güncellemeleri, güvenlik duvarı, açık portlar, SSH yapılandırması,
başarısız giriş denemeleri ve diğer güvenlik kontrollerini yapar.

Modül Yapısı:
    models.py          - Veri modelleri (SecuritySummary, PortInfo, SSHAudit)
    enums.py           - Güvenlik seviyeleri (SecurityLevel, SSHSecurityLevel)
    summary.py         - Sistem güvenlik özeti
    ports.py           - Açık port tarama ve analiz
    login_attempts.py  - Başarısız giriş denemesi analizi
    ssh/               - SSH yapılandırma denetimi (alt modül)
        audit.py       - SSH denetim fonksiyonları
        validators.py  - Doğrulama fonksiyonları
        rules.py       - Kural tanımları
        parsers.py     - Parse helper'ları

Public API - Ana Fonksiyonlar:
    get_security_summary()         - Sistem güvenlik özeti
    get_listening_ports()          - Açık portları listele
    audit_ssh_config()             - SSH yapılandırmasını denetle
    audit_multiple_ssh_configs()   - Birden fazla SSH config denetle
    check_failed_login_attempts()  - Başarısız giriş denemelerini analiz et

Public API - Veri Modelleri:
    SecuritySummary  - Sistem güvenlik özet bilgileri (dataclass)
    PortInfo         - Ağ port bilgileri (dataclass)
    SSHAudit         - SSH denetim sonuçları (dataclass)

Public API - Enum'lar:
    SecurityLevel      - Güvenlik seviyesi (EXCELLENT, GOOD, FAIR, POOR, CRITICAL)
    SSHSecurityLevel   - SSH güvenlik seviyesi (CRITICAL, HIGH, MEDIUM, LOW, INFO)

Örnekler:
    >>> # Temel kullanım
    >>> from linux_teknikeri.checks.security import (
    ...     get_security_summary,
    ...     SecurityLevel
    ... )
    >>> 
    >>> summary = get_security_summary()
    >>> print(f"Güvenlik Skoru: {summary['get_security_score']()}/100")
    >>> 
    >>> # SecuritySummary dataclass ile
    >>> from linux_teknikeri.checks.security import SecuritySummary
    >>> summary_obj = SecuritySummary(
    ...     security_updates_count=5,
    ...     firewall_status="Aktif",
    ...     apparmor_status="Aktif",
    ...     selinux_status="Kurulu Değil",
    ...     unattended_upgrades="Aktif",
    ...     last_update_check="Bugün"
    ... )
    >>> if summary_obj.has_critical_issues():
    ...     print("⚠️  Kritik güvenlik sorunu!")
    >>> 
    >>> # Port tarama
    >>> from linux_teknikeri.checks.security import get_listening_ports
    >>> ports = get_listening_ports()
    >>> public_ports = [p for p in ports if p['address'] == '0.0.0.0']
    >>> print(f"{len(public_ports)} public port bulundu")
    >>> 
    >>> # SSH denetimi
    >>> from linux_teknikeri.checks.security import audit_ssh_config
    >>> ssh_audit = audit_ssh_config()
    >>> if ssh_audit['risk_level'] == 'CRITICAL':
    ...     print("🔴 SSH yapılandırması kritik risk seviyesinde!")

Notlar:
    - Tüm fonksiyonlar exception raise etmez, hataları dict/dataclass içinde döner
    - Sudo yetkisi gereken fonksiyonlar var (özellikle port tarama ve SSH audit)
    - Log'lama için logging modülü kullanılır
    - Type hints tam olarak tanımlanmıştır (mypy uyumlu)

Author: ozturu68
Version: 0.5.0
Date: 2025-11-01
License: MIT

See Also:
    - check_security.py: Ana API giriş noktası (geriye uyumluluk)
    - checks/__init__.py: Tüm check modüllerinin export'u
"""

# Standard library imports
import logging
from typing import Dict, List, Optional, Any
from pathlib import Path

# Veri modelleri (dataclass'lar)
from .models import (
    SecuritySummary,
    PortInfo,
    SSHAudit,
)

# Enum'lar (güvenlik seviyeleri)
from .enums import (
    SecurityLevel,
    SSHSecurityLevel,
)

# Ana fonksiyonlar
from .summary import get_security_summary
from .ports import get_listening_ports
from .ssh import audit_ssh_config, audit_multiple_ssh_configs
from .login_attempts import check_failed_login_attempts

# Logger
log = logging.getLogger(__name__)

# Modül versiyonu
__version__ = '0.5.0'

# Public API (tüm export edilen isimler)
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
    
    # === METADATA ===
    '__version__',        # Modül versiyonu
]


# =============================================================================
# MODULE INITIALIZATION
# =============================================================================

def _check_dependencies() -> bool:
    """
    Modül bağımlılıklarını kontrol eder.
    
    Returns:
        bool: Tüm bağımlılıklar hazırsa True
    
    Note:
        Bu fonksiyon modül import edilirken otomatik çalışır.
        Eksik bağımlılık varsa warning log'lar ama crash etmez.
    """
    missing_deps = []
    
    # Command runner modülü
    try:
        from ...utils.command_runner import run_command
    except ImportError:
        missing_deps.append('utils.command_runner')
    
    # Eğer eksik bağımlılık varsa uyar
    if missing_deps:
        log.warning(
            f"Güvenlik modülü eksik bağımlılıklar ile yüklendi: {', '.join(missing_deps)}"
        )
        return False
    
    return True


# Modül yüklenirken bağımlılık kontrolü yap
_dependencies_ok = _check_dependencies()

if not _dependencies_ok:
    log.warning(
        "⚠️  Güvenlik modülü bazı özellikler kısıtlı modda çalışacak. "
        "Tam işlevsellik için tüm bağımlılıkları yükleyin."
    )


# =============================================================================
# CONVENIENCE FUNCTIONS (Opsiyonel yardımcı fonksiyonlar)
# =============================================================================

def get_full_security_report() -> Dict[str, Any]:
    """
    Tüm güvenlik kontrollerini tek seferde çalıştırır.
    
    Bu fonksiyon tüm güvenlik modüllerini çalıştırıp tek bir raporda toplar.
    Performans nedeniyle dikkatli kullanın (10-30 saniye sürebilir).
    
    Returns:
        Dict[str, Any]: Kapsamlı güvenlik raporu
            {
                'summary': Dict,           # get_security_summary() sonucu
                'ports': List[Dict],       # get_listening_ports() sonucu
                'ssh_audit': Dict,         # audit_ssh_config() sonucu
                'failed_logins': Dict,     # check_failed_login_attempts() sonucu
                'timestamp': str,          # Rapor zamanı (ISO format)
                'overall_score': int,      # Genel güvenlik skoru (0-100)
                'risk_level': str,         # Genel risk seviyesi
            }
    
    Examples:
        >>> report = get_full_security_report()
        >>> print(f"Genel Skor: {report['overall_score']}/100")
        >>> print(f"Risk Seviyesi: {report['risk_level']}")
        >>> 
        >>> # Detaylı bilgiye eriş
        >>> if report['ssh_audit']['risk_level'] == 'CRITICAL':
        ...     print("SSH yapılandırması kritik!")
        >>> 
        >>> if report['failed_logins']['total_failed'] > 100:
        ...     print("Çok fazla başarısız giriş denemesi!")
    
    Note:
        - Bu fonksiyon tüm kontrolleri sırayla çalıştırır (10-30 saniye)
        - Sudo yetkisi gerekebilir
        - Hata durumunda kısmi rapor döner (crash etmez)
    
    Performance:
        - get_security_summary(): ~2-5 saniye
        - get_listening_ports(): ~1-3 saniye
        - audit_ssh_config(): ~1 saniye
        - check_failed_login_attempts(): ~5-20 saniye
    """
    from datetime import datetime
    
    log.info("Kapsamlı güvenlik raporu oluşturuluyor...")
    
    report = {
        'timestamp': datetime.now().isoformat(),
        'overall_score': 0,
        'risk_level': 'UNKNOWN',
    }
    
    # 1. Güvenlik özeti
    try:
        summary = get_security_summary()
        report['summary'] = summary
        log.debug("✅ Güvenlik özeti alındı")
    except Exception as e:
        log.error(f"Güvenlik özeti alınamadı: {e}")
        report['summary'] = {'error': str(e)}
    
    # 2. Açık portlar
    try:
        ports = get_listening_ports()
        report['ports'] = ports
        log.debug(f"✅ {len(ports)} port tarandı")
    except Exception as e:
        log.error(f"Port tarama başarısız: {e}")
        report['ports'] = []
    
    # 3. SSH denetimi
    try:
        ssh_audit = audit_ssh_config()
        report['ssh_audit'] = ssh_audit
        log.debug(f"✅ SSH denetimi tamamlandı (risk: {ssh_audit.get('risk_level', 'N/A')})")
    except Exception as e:
        log.error(f"SSH denetimi başarısız: {e}")
        report['ssh_audit'] = {'error': str(e)}
    
    # 4. Başarısız giriş denemeleri
    try:
        failed_logins = check_failed_login_attempts()
        report['failed_logins'] = failed_logins
        log.debug(f"✅ Başarısız giriş analizi tamamlandı ({failed_logins.get('total_failed', 0)} deneme)")
    except Exception as e:
        log.error(f"Başarısız giriş analizi başarısız: {e}")
        report['failed_logins'] = {'error': str(e)}
    
    # Genel skor ve risk seviyesi hesapla
    try:
        report['overall_score'] = _calculate_overall_score(report)
        report['risk_level'] = _calculate_risk_level(report['overall_score'])
    except Exception as e:
        log.error(f"Genel skor hesaplanamadı: {e}")
    
    log.info(f"Kapsamlı güvenlik raporu hazır (skor: {report['overall_score']}/100)")
    return report


def _calculate_overall_score(report: Dict[str, Any]) -> int:
    """
    Tüm kontrolleri birleştirerek genel skor hesaplar.
    
    Args:
        report: get_full_security_report() çıktısı
    
    Returns:
        int: Genel güvenlik skoru (0-100)
    """
    scores = []
    
    # Güvenlik özeti skoru (ağırlık: 40%)
    if 'summary' in report and 'error' not in report['summary']:
        # SecuritySummary'den skor al (eğer varsa)
        # Not: summary dict formatında, get_security_score() çağrılamaz
        # Bu yüzden basit hesaplama yapıyoruz
        summary = report['summary']
        summary_score = 100
        
        if summary.get('security_updates_count', 0) > 10:
            summary_score -= 30
        elif summary.get('security_updates_count', 0) > 0:
            summary_score -= summary['security_updates_count'] * 2
        
        if 'Devre Dışı' in summary.get('firewall_status', '') or 'Kurulu Değil' in summary.get('firewall_status', ''):
            summary_score -= 30
        
        scores.append(('summary', summary_score, 0.4))
    
    # SSH audit skoru (ağırlık: 30%)
    if 'ssh_audit' in report and 'error' not in report['ssh_audit']:
        ssh = report['ssh_audit']
        ssh_score = 100
        
        if ssh.get('risk_level') == 'CRITICAL':
            ssh_score = 20
        elif ssh.get('risk_level') == 'HIGH':
            ssh_score = 50
        elif ssh.get('risk_level') == 'MEDIUM':
            ssh_score = 70
        
        scores.append(('ssh', ssh_score, 0.3))
    
    # Başarısız giriş skoru (ağırlık: 20%)
    if 'failed_logins' in report and 'error' not in report['failed_logins']:
        failed = report['failed_logins']
        failed_score = 100
        
        total = failed.get('total_failed', 0)
        if total > 1000:
            failed_score = 30
        elif total > 100:
            failed_score = 60
        elif total > 10:
            failed_score = 80
        
        scores.append(('failed_logins', failed_score, 0.2))
    
    # Port skoru (ağırlık: 10%)
    if 'ports' in report and isinstance(report['ports'], list):
        port_count = len(report['ports'])
        port_score = 100
        
        if port_count > 50:
            port_score = 60
        elif port_count > 20:
            port_score = 80
        
        scores.append(('ports', port_score, 0.1))
    
    # Ağırlıklı ortalama hesapla
    if not scores:
        return 50  # Hiçbir skor hesaplanamadıysa orta değer
    
    weighted_sum = sum(score * weight for _, score, weight in scores)
    total_weight = sum(weight for _, _, weight in scores)
    
    overall = int(weighted_sum / total_weight) if total_weight > 0 else 50
    
    return max(0, min(100, overall))


def _calculate_risk_level(score: int) -> str:
    """
    Skora göre risk seviyesi belirler.
    
    Args:
        score: Güvenlik skoru (0-100)
    
    Returns:
        str: Risk seviyesi
    """
    if score >= 90:
        return "EXCELLENT"
    elif score >= 70:
        return "GOOD"
    elif score >= 50:
        return "FAIR"
    elif score >= 30:
        return "POOR"
    else:
        return "CRITICAL"


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

log.debug(f"Güvenlik modülü yüklendi (v{__version__})")