"""
SSH Yapılandırma Denetim Fonksiyonu
====================================

SSH config'i analiz eden ana fonksiyonlar.

Bu modül SSH yapılandırmasını denetleyen üst seviye fonksiyonları içerir.
Tüm SSH modülünün giriş noktasıdır.

Fonksiyonlar:
    audit_ssh_config()             - Ana denetim fonksiyonu (tek config)
    audit_multiple_ssh_configs()   - Batch denetim (birden fazla config)
    _create_audit_result()         - Audit sonucu oluşturur (helper)
    _handle_audit_error()          - Hata handling (helper)

Denetim Akışı:
    1. Config dosyası okunur (_read_ssh_config)
    2. SSHAudit başlatılır
    3. Kurallar uygulanır (_apply_ssh_rules)
    4. Risk seviyesi hesaplanır (SSHAudit.__post_init__)
    5. Sonuç dictionary olarak döndürülür

Author: ozturu68
Version: 0.5.0
Date: 2025-11-01
License: MIT
"""

import logging
from pathlib import Path
from typing import Dict, List, Optional, Any

# Local imports
from .parsers import (
    _read_ssh_config,
    _apply_ssh_rules,
)
from ..models import SSHAudit

# Logger
log = logging.getLogger(__name__)


# =============================================================================
# ANA FONKSİYON - TEK CONFIG DENETİMİ
# =============================================================================

def audit_ssh_config(
    config_path: Optional[Path] = None
) -> Dict[str, Any]:
    """
    SSH yapılandırmasını güvenlik açısından denetler.
    
    /etc/ssh/sshd_config dosyasını analiz ederek kritik güvenlik ayarlarını
    kontrol eder ve risk değerlendirmesi yapar.
    
    Args:
        config_path (Optional[Path]): SSH config dosya yolu
            - None: Varsayılan (/etc/ssh/sshd_config)
            - Path: Özel config dosyası
    
    Returns:
        Dict[str, Any]: SSH yapılandırma denetim sonuçları
            {
                'config_exists': bool,                    # Config mevcut mu
                'port': str,                              # SSH port
                'root_login_permitted': Optional[bool],   # Root giriş izni
                'password_auth_enabled': Optional[bool],  # Şifre ile giriş
                'empty_passwords_permitted': Optional[bool], # Boş şifre (KRİTİK!)
                'ssh_protocol': Optional[str],            # Protokol versiyonu
                'permit_user_environment': Optional[bool],# User environment
                'x11_forwarding': Optional[bool],         # X11 forwarding
                'max_auth_tries': Optional[int],          # Max giriş denemesi
                'recommendations': List[str],             # Güvenlik önerileri
                'risk_level': str,                        # Risk seviyesi
            }
    
    Security Checks:
        1. PermitRootLogin         - Root kullanıcı girişi
        2. PasswordAuthentication  - Şifre ile giriş
        3. PermitEmptyPasswords    - Boş şifre izni (KRİTİK!)
        4. Protocol                - SSH protokol versiyonu
        5. Port                    - SSH port numarası
        6. X11Forwarding           - X11 yönlendirme
        7. PermitUserEnvironment   - Kullanıcı ortam değişkenleri
        8. MaxAuthTries            - Maksimum giriş denemesi
    
    Risk Levels:
        - CRITICAL: Boş şifre izni var (acil müdahale!)
        - HIGH:     Root + şifre girişi aktif (ciddi risk)
        - MEDIUM:   Root veya varsayılan port + şifre (orta risk)
        - LOW:      Güvenli yapılandırma
    
    Examples:
        >>> from pathlib import Path
        >>> from linux_teknikeri.checks.security.ssh import audit_ssh_config
        >>> 
        >>> # Varsayılan kullanım
        >>> audit = audit_ssh_config()
        >>> print(f"Risk: {audit['risk_level']}")
        Risk: HIGH
        >>> 
        >>> # Öneriler
        >>> for rec in audit['recommendations']:
        ...     print(f"  • {rec}")
        >>> 
        >>> # Kritik kontrol
        >>> if audit['risk_level'] == 'CRITICAL':
        ...     print("🔴 ACİL MÜDAHALE GEREKLİ!")
        >>> 
        >>> # Özel config dosyası
        >>> custom_audit = audit_ssh_config(Path("/custom/sshd_config"))
        >>> 
        >>> # Risk kontrolü
        >>> if audit['root_login_permitted']:
        ...     print("⚠️  Root girişi aktif - güvenlik riski!")
        >>> 
        >>> # SSHAudit dataclass'a çevirme
        >>> from linux_teknikeri.checks.security import SSHAudit
        >>> ssh_obj = SSHAudit(**audit)
        >>> score = ssh_obj.get_security_score()
        >>> print(f"SSH Skoru: {score}/100")
        SSH Skoru: 60/100
    
    Performance:
        Ortalama süre: ~1 saniye
        - Config okuma: ~0.1 saniye
        - Parse: ~0.3 saniye
        - Validation: ~0.3 saniye
        - Risk hesaplama: ~0.1 saniye
    
    Note:
        - Dosya okuma yetkisi gerektirir (/etc/ssh/sshd_config genellikle root-readable)
        - Sadece /etc/ssh/sshd_config kontrol edilir, include dosyaları opsiyoneldir
        - OpenSSH yapılandırması baz alınmıştır
        - Exception raise etmez, hataları audit sonucuna ekler
    
    See Also:
        - sshd_config(5): SSH daemon yapılandırma man sayfası
        - SSHAudit: Denetim sonuç dataclass'ı
        - audit_multiple_ssh_configs(): Batch denetim
        - get_security_summary(): Genel güvenlik özeti
    
    Raises:
        Herhangi bir exception raise etmez, hata durumlarını dict içinde döner.
    """
    log.info("SSH yapılandırma denetimi başlatılıyor...")
    
    # Config path varsayılanı
    if config_path is None:
        config_path = Path("/etc/ssh/sshd_config")
    
    log.debug(f"SSH config path: {config_path}")
    
    # Başlangıç audit sonucu
    audit_result = _create_audit_result(config_exists=False, port='22')
    
    # Config dosyası kontrolü ve okuma
    try:
        config_content = _read_ssh_config(config_path)
        audit_result.config_exists = True
        log.debug(f"SSH config okundu: {len(config_content)} byte")
    
    except ValueError as e:
        # Dosya bulunamadı
        log.info(f"SSH config bulunamadı: {e}")
        audit_result.add_recommendation(
            "ℹ️  SSH sunucusu kurulu değil veya yapılandırma dosyası bulunamadı."
        )
        return audit_result.to_dict()
    
    except PermissionError:
        # Okuma yetkisi yok
        log.warning("SSH config okuma yetkisi yok")
        audit_result.config_exists = True  # Var ama okunamıyor
        audit_result.add_recommendation(
            "⚠️  SSH yapılandırması okunamadı (yetki gerekli). "
            "Denetim için: sudo python3 -m linux_teknikeri"
        )
        return audit_result.to_dict()
    
    except Exception as e:
        # Diğer hatalar
        log.error(f"SSH config okuma hatası: {e}", exc_info=True)
        return _handle_audit_error(audit_result, e)
    
    # Kuralları uygula
    try:
        _apply_ssh_rules(config_content, audit_result)
        log.info(
            f"SSH denetimi tamamlandı: "
            f"Risk={audit_result.risk_level}, "
            f"Öneri={len(audit_result.recommendations)}"
        )
    
    except Exception as e:
        log.error(f"SSH kural uygulama hatası: {e}", exc_info=True)
        audit_result.add_recommendation(
            f"⚠️  Bazı ayarlar kontrol edilemedi: {str(e)}"
        )
    
    return audit_result.to_dict()


# =============================================================================
# BATCH FONKSİYON - ÇOK CONFIG DENETİMİ
# =============================================================================

def audit_multiple_ssh_configs(
    config_paths: List[Path]
) -> Dict[Path, Dict[str, Any]]:
    """
    Birden fazla SSH config dosyasını denetler (batch işlem).
    
    Args:
        config_paths: Config dosya yolları listesi
    
    Returns:
        Dict[Path, Dict[str, Any]]: Her dosya için audit sonucu
            {
                Path("/etc/ssh/sshd_config"): {...},
                Path("/etc/ssh/sshd_config.d/custom.conf"): {...},
            }
    
    Examples:
        >>> from pathlib import Path
        >>> 
        >>> # Birden fazla config
        >>> configs = [
        ...     Path("/etc/ssh/sshd_config"),
        ...     Path("/etc/ssh/sshd_config.d/custom.conf")
        ... ]
        >>> 
        >>> results = audit_multiple_ssh_configs(configs)
        >>> 
        >>> # Her config için sonuç
        >>> for path, audit in results.items():
        ...     print(f"{path.name}: {audit['risk_level']}")
        sshd_config: HIGH
        custom.conf: LOW
        >>> 
        >>> # Kritik olanları bul
        >>> critical = [
        ...     path for path, audit in results.items()
        ...     if audit['risk_level'] == 'CRITICAL'
        ... ]
        >>> if critical:
        ...     print(f"Kritik config'ler: {critical}")
    
    Performance:
        - Süre: ~N saniye (N = config sayısı)
        - Sıralı işlenir (paralel değil)
    
    Note:
        - Her config bağımsız denetlenir
        - Bir config'deki hata diğerlerini etkilemez
        - Hata durumunda o config için error field'ı döner
    
    See Also:
        - audit_ssh_config(): Tek config denetimi
    """
    log.info(f"Batch SSH denetimi başlatılıyor: {len(config_paths)} config")
    
    results = {}
    
    for config_path in config_paths:
        try:
            audit = audit_ssh_config(config_path)
            results[config_path] = audit
            log.debug(f"Config denetlendi: {config_path} → {audit['risk_level']}")
        
        except Exception as e:
            log.error(f"Config audit hatası ({config_path}): {e}")
            results[config_path] = {
                'error': str(e),
                'config_exists': False,
                'risk_level': 'UNKNOWN',
            }
    
    log.info(f"Batch SSH denetimi tamamlandı: {len(results)} sonuç")
    return results


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _create_audit_result(
    config_exists: bool,
    port: str
) -> SSHAudit:
    """
    Başlangıç audit sonucu oluşturur (helper).
    
    Args:
        config_exists: Config dosyası mevcut mu
        port: Varsayılan port (genellikle "22")
    
    Returns:
        SSHAudit: Boş audit sonucu
    
    Note:
        Tüm opsiyonel field'lar None ile başlar.
    """
    return SSHAudit(
        config_exists=config_exists,
        port=port,
        root_login_permitted=None,
        password_auth_enabled=None,
        empty_passwords_permitted=None,
        ssh_protocol=None,
        permit_user_environment=None,
        x11_forwarding=None,
        max_auth_tries=None,
    )


def _handle_audit_error(
    audit_result: SSHAudit,
    error: Exception
) -> Dict[str, Any]:
    """
    Denetim hatalarını handle eder (helper).
    
    Args:
        audit_result: Mevcut audit sonucu
        error: Oluşan hata
    
    Returns:
        Dict[str, Any]: Hata bilgisi içeren audit sonucu
    
    Note:
        Exception raise etmez, hata mesajını audit'e ekler.
    """
    error_message = f"❌ SSH denetim hatası: {str(error)}"
    audit_result.add_recommendation(error_message)
    log.error(error_message, exc_info=True)
    return audit_result.to_dict()


def get_audit_summary(audit: Dict[str, Any]) -> str:
    """
    Audit sonucunun kısa özetini metin olarak döndürür (bonus).
    
    Args:
        audit: audit_ssh_config() sonucu
    
    Returns:
        str: Özet metin (çok satırlı)
    
    Examples:
        >>> audit = audit_ssh_config()
        >>> summary = get_audit_summary(audit)
        >>> print(summary)
        SSH Denetim Özeti
        =================
        Risk Seviyesi: HIGH 🔴
        Config Mevcut: Evet
        ...
    """
    # Risk emoji
    risk_emojis = {
        'CRITICAL': '🔴🔴🔴',
        'HIGH': '🔴',
        'MEDIUM': '⚠️',
        'LOW': '✅',
        'UNKNOWN': '❓',
    }
    risk_emoji = risk_emojis.get(audit.get('risk_level', 'UNKNOWN'), '❓')
    
    lines = [
        "SSH Denetim Özeti",
        "=" * 50,
        f"Risk Seviyesi: {audit.get('risk_level', 'UNKNOWN')} {risk_emoji}",
        f"Config Mevcut: {'Evet' if audit.get('config_exists') else 'Hayır'}",
        f"Port: {audit.get('port', 'Bilinmiyor')}",
        "",
        "Ayarlar:",
    ]
    
    # Ayarları göster
    settings = [
        ('Root Giriş', audit.get('root_login_permitted')),
        ('Şifre ile Giriş', audit.get('password_auth_enabled')),
        ('Boş Şifre İzni', audit.get('empty_passwords_permitted')),
        ('SSH Protokol', audit.get('ssh_protocol')),
        ('X11 Forwarding', audit.get('x11_forwarding')),
        ('User Environment', audit.get('permit_user_environment')),
        ('Max Auth Tries', audit.get('max_auth_tries')),
    ]
    
    for name, value in settings:
        if value is None:
            status = "Belirtilmemiş"
        elif value is True:
            status = "Aktif"
        elif value is False:
            status = "Kapalı"
        else:
            status = str(value)
        
        lines.append(f"  • {name}: {status}")
    
    lines.append("")
    lines.append(f"Öneriler ({len(audit.get('recommendations', []))}):")
    
    for i, rec in enumerate(audit.get('recommendations', [])[:5], 1):
        # İlk 5 öneri
        lines.append(f"  {i}. {rec[:80]}...")
    
    if len(audit.get('recommendations', [])) > 5:
        lines.append(f"  ... ve {len(audit['recommendations']) - 5} öneri daha")
    
    return "\n".join(lines)


def compare_configs(
    audit1: Dict[str, Any],
    audit2: Dict[str, Any]
) -> Dict[str, Any]:
    """
    İki SSH audit sonucunu karşılaştırır (bonus).
    
    Args:
        audit1: İlk audit sonucu
        audit2: İkinci audit sonucu
    
    Returns:
        Dict[str, Any]: Karşılaştırma sonucu
            {
                'differences': List[str],      # Farklar
                'risk_change': str,            # Risk değişimi
                'improvements': List[str],     # İyileştirmeler
                'regressions': List[str],      # Kötüleşmeler
            }
    
    Examples:
        >>> old_audit = audit_ssh_config(Path("old_sshd_config"))
        >>> new_audit = audit_ssh_config(Path("new_sshd_config"))
        >>> 
        >>> comparison = compare_configs(old_audit, new_audit)
        >>> 
        >>> print(f"Risk değişimi: {comparison['risk_change']}")
        >>> for improvement in comparison['improvements']:
        ...     print(f"✅ {improvement}")
    """
    differences = []
    improvements = []
    regressions = []
    
    # Risk seviyesi karşılaştırması
    risk_levels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    risk1_idx = risk_levels.index(audit1.get('risk_level', 'MEDIUM'))
    risk2_idx = risk_levels.index(audit2.get('risk_level', 'MEDIUM'))
    
    if risk2_idx < risk1_idx:
        risk_change = "İyileşti"
        improvements.append(
            f"Risk seviyesi düştü: {audit1['risk_level']} → {audit2['risk_level']}"
        )
    elif risk2_idx > risk1_idx:
        risk_change = "Kötüleşti"
        regressions.append(
            f"Risk seviyesi arttı: {audit1['risk_level']} → {audit2['risk_level']}"
        )
    else:
        risk_change = "Değişmedi"
    
    # Ayar karşılaştırması
    settings = [
        'root_login_permitted',
        'password_auth_enabled',
        'empty_passwords_permitted',
        'x11_forwarding',
        'permit_user_environment',
    ]
    
    for setting in settings:
        val1 = audit1.get(setting)
        val2 = audit2.get(setting)
        
        if val1 != val2:
            differences.append(f"{setting}: {val1} → {val2}")
            
            # İyileşme mi kötüleşme mi?
            # True → False: İyileşme (riskli ayarlar kapatıldı)
            if val1 is True and val2 is False:
                improvements.append(f"{setting} kapatıldı (iyi)")
            elif val1 is False and val2 is True:
                regressions.append(f"{setting} açıldı (kötü)")
    
    return {
        'differences': differences,
        'risk_change': risk_change,
        'improvements': improvements,
        'regressions': regressions,
    }


def generate_fix_commands(audit: Dict[str, Any]) -> List[str]:
    """
    Audit sonucuna göre düzeltme komutları üretir (bonus).
    
    Args:
        audit: audit_ssh_config() sonucu
    
    Returns:
        List[str]: Düzeltme komutları
    
    Examples:
        >>> audit = audit_ssh_config()
        >>> commands = generate_fix_commands(audit)
        >>> 
        >>> print("Düzeltme komutları:")
        >>> for cmd in commands:
        ...     print(f"  {cmd}")
        sudo sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
        sudo sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
        sudo systemctl reload sshd
    
    Warning:
        Bu komutlar otomatik oluşturulur, dikkatlice kullanın!
        Yedek almadan uygulamayın!
    """
    commands = [
        "# SSH Güvenlik Düzeltme Komutları",
        "# UYARI: Yedek alın!",
        "sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup",
        "",
    ]
    
    # Root login
    if audit.get('root_login_permitted'):
        commands.append(
            "# Root girişini kapat"
        )
        commands.append(
            "sudo sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config"
        )
        commands.append("")
    
    # Password auth
    if audit.get('password_auth_enabled'):
        commands.append(
            "# Şifre ile girişi kapat (SSH key kullanın)"
        )
        commands.append(
            "sudo sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config"
        )
        commands.append("")
    
    # Empty passwords (KRİTİK!)
    if audit.get('empty_passwords_permitted'):
        commands.append(
            "# KRİTİK: Boş şifre iznini kapat"
        )
        commands.append(
            "sudo sed -i 's/^PermitEmptyPasswords yes/PermitEmptyPasswords no/' /etc/ssh/sshd_config"
        )
        commands.append("")
    
    # Config test ve reload
    commands.extend([
        "# Config'i test et",
        "sudo sshd -t",
        "",
        "# Değişiklikleri uygula",
        "sudo systemctl reload sshd",
        "",
        "# NOT: SSH bağlantınızı kaybetmeden önce yeni bir terminal açıp test edin!",
    ])
    
    return commands


# =============================================================================
# MODULE METADATA
# =============================================================================

__all__ = [
    'audit_ssh_config',
    'audit_multiple_ssh_configs',
    'get_audit_summary',
    'compare_configs',
    'generate_fix_commands',
]