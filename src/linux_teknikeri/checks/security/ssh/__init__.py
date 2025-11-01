"""
SSH Güvenlik Denetim Modülü
============================

SSH yapılandırmasını analiz eden ve güvenlik açıklarını tespit eden alt modül.

Bu modül SSH sunucusunun güvenlik yapılandırmasını kapsamlı şekilde denetler.
Root girişi, şifre doğrulama, boş şifre izni gibi kritik güvenlik ayarlarını
kontrol eder ve risk değerlendirmesi yapar.

Modül Yapısı:
    audit.py       - Ana denetim fonksiyonu (audit_ssh_config)
    validators.py  - Doğrulama fonksiyonları (8 validator)
    rules.py       - Kural tanımları (SSHConfigRule, SSH_CONFIG_RULES)
    parsers.py     - Parse helper'ları (config okuma, parse)

Public API - Ana Fonksiyonlar:
    audit_ssh_config()             - SSH config'i denetle
    audit_multiple_ssh_configs()   - Birden fazla config denetle (batch)

Public API - Veri Modelleri:
    SSHAudit         - SSH denetim sonuçları (dataclass, models.py'den)
    SSHConfigRule    - SSH kural tanımı (dataclass, rules.py'den)
    SSHSecurityLevel - SSH güvenlik seviyesi (enum, enums.py'den)

Public API - Kurallar:
    SSH_CONFIG_RULES - Tüm SSH kuralları listesi (rules.py'den)

Kontrol Edilen SSH Ayarları:
    1. PermitRootLogin         - Root girişi izni (KRİTİK)
    2. PasswordAuthentication  - Şifre ile giriş
    3. PermitEmptyPasswords    - Boş şifre izni (ÇOK KRİTİK!)
    4. Protocol                - SSH protokol versiyonu (1 vs 2)
    5. Port                    - SSH port numarası
    6. X11Forwarding           - X11 yönlendirme
    7. PermitUserEnvironment   - Kullanıcı ortam değişkenleri
    8. MaxAuthTries            - Maksimum giriş denemesi

Risk Seviyeleri:
    CRITICAL - Boş şifre izni var (acil müdahale!)
    HIGH     - Root + şifre girişi aktif (ciddi risk)
    MEDIUM   - Root veya varsayılan port + şifre (orta risk)
    LOW      - Güvenli yapılandırma

Örnekler:
    >>> from linux_teknikeri.checks.security.ssh import (
    ...     audit_ssh_config,
    ...     audit_multiple_ssh_configs
    ... )
    >>> 
    >>> # Temel kullanım
    >>> audit = audit_ssh_config()
    >>> print(f"Risk Seviyesi: {audit['risk_level']}")
    Risk Seviyesi: HIGH
    >>> 
    >>> # Öneriler
    >>> for rec in audit['recommendations']:
    ...     print(f"  • {rec}")
    >>> 
    >>> # Güvenlik skoru
    >>> from linux_teknikeri.checks.security import SSHAudit
    >>> ssh_obj = SSHAudit(**audit)
    >>> score = ssh_obj.get_security_score()
    >>> print(f"SSH Skoru: {score}/100")
    SSH Skoru: 60/100
    >>> 
    >>> # Özel config dosyası
    >>> from pathlib import Path
    >>> custom_audit = audit_ssh_config(Path("/custom/sshd_config"))
    >>> 
    >>> # Batch denetim (birden fazla config)
    >>> configs = [
    ...     Path("/etc/ssh/sshd_config"),
    ...     Path("/etc/ssh/sshd_config.d/custom.conf")
    ... ]
    >>> results = audit_multiple_ssh_configs(configs)
    >>> for path, audit_result in results.items():
    ...     print(f"{path}: {audit_result['risk_level']}")

Güvenlik En İyi Uygulamaları:
    ✅ PermitRootLogin no
    ✅ PasswordAuthentication no (SSH key kullanın)
    ✅ PermitEmptyPasswords no
    ✅ Protocol 2
    ✅ Port 2222 (veya özel port, brute-force'u azaltır)
    ✅ X11Forwarding no
    ✅ PermitUserEnvironment no
    ✅ MaxAuthTries 3

Notlar:
    - Config okuma yetkisi gerektirir (/etc/ssh/sshd_config genellikle root-readable)
    - Sadece /etc/ssh/sshd_config kontrol edilir, include dosyaları opsiyoneldir
    - OpenSSH yapılandırması baz alınmıştır
    - Exception raise etmez, hataları audit sonucuna ekler

Performans:
    - Tek config denetimi: ~1 saniye
    - Batch denetim: ~N saniye (N = config sayısı)

See Also:
    - sshd_config(5): SSH daemon yapılandırma man sayfası
    - ssh(1): SSH client man sayfası
    - get_security_summary(): Genel güvenlik özeti
    - check_failed_login_attempts(): Başarısız giriş analizi

Author: ozturu68
Version: 0.5.0
Date: 2025-11-01
License: MIT
"""

# Standard library imports
import logging
from typing import Dict, List, Any
from pathlib import Path

# Local imports - Public API
from .audit import (
    audit_ssh_config,
    audit_multiple_ssh_configs,
)

# Local imports - Internal (not exported)
from .validators import *  # 8 validator fonksiyon
from .rules import SSH_CONFIG_RULES, SSHConfigRule
from .parsers import *  # Helper fonksiyonlar

# Parent imports (dataclass'lar ve enum'lar)
from ..models import SSHAudit
from ..enums import SSHSecurityLevel

# Logger
log = logging.getLogger(__name__)

# Modül versiyonu
__version__ = '0.5.0'

# Public API (tüm export edilen isimler)
__all__ = [
    # === ANA FONKSİYONLAR ===
    'audit_ssh_config',            # SSH config denetimi
    'audit_multiple_ssh_configs',  # Çoklu config denetimi (batch)
    
    # === DATACLASS'LAR (re-export) ===
    'SSHAudit',                    # SSH denetim sonuçları
    'SSHConfigRule',               # SSH kural tanımı
    
    # === ENUM'LAR (re-export) ===
    'SSHSecurityLevel',            # SSH güvenlik seviyesi
    
    # === KURALLAR ===
    'SSH_CONFIG_RULES',            # Tüm SSH kuralları listesi
    
    # === METADATA ===
    '__version__',                 # Modül versiyonu
]


# =============================================================================
# MODULE INITIALIZATION
# =============================================================================

def _check_ssh_dependencies() -> bool:
    """
    SSH modülü bağımlılıklarını kontrol eder.
    
    Returns:
        bool: Tüm bağımlılıklar hazırsa True
    
    Note:
        Bu fonksiyon modül import edilirken otomatik çalışır.
        Eksik bağımlılık varsa warning log'lar ama crash etmez.
    """
    missing_deps = []
    
    # Config okuma yetkisi kontrolü
    ssh_config_path = Path("/etc/ssh/sshd_config")
    if not ssh_config_path.exists():
        log.debug("SSH config dosyası bulunamadı (SSH sunucusu kurulu değil olabilir)")
        missing_deps.append('sshd_config')
    elif not ssh_config_path.is_file():
        log.warning(f"{ssh_config_path} bir dosya değil")
        missing_deps.append('sshd_config')
    
    # Validator fonksiyonlarını kontrol et
    try:
        from .validators import (
            _validate_root_login,
            _validate_password_auth,
            _validate_empty_passwords,
            _validate_protocol,
            _validate_port,
            _validate_x11_forwarding,
            _validate_user_environment,
            _validate_max_auth_tries,
        )
    except ImportError as e:
        log.error(f"Validator fonksiyonları import edilemedi: {e}")
        missing_deps.append('validators')
    
    # Kuralları kontrol et
    try:
        from .rules import SSH_CONFIG_RULES
        if not SSH_CONFIG_RULES:
            log.warning("SSH_CONFIG_RULES listesi boş!")
            missing_deps.append('rules')
    except ImportError as e:
        log.error(f"SSH kuralları import edilemedi: {e}")
        missing_deps.append('rules')
    
    # Eğer eksik bağımlılık varsa uyar
    if missing_deps:
        log.warning(
            f"SSH modülü eksik bağımlılıklar ile yüklendi: {', '.join(missing_deps)}"
        )
        return False
    
    return True


# Modül yüklenirken bağımlılık kontrolü yap
_dependencies_ok = _check_ssh_dependencies()

if not _dependencies_ok:
    log.warning(
        "⚠️  SSH modülü bazı özellikler kısıtlı modda çalışacak. "
        "Tam işlevsellik için SSH sunucusu kurulu olmalı."
    )
else:
    log.debug(f"SSH modülü başarıyla yüklendi (v{__version__})")


# =============================================================================
# CONVENIENCE FUNCTIONS (Yardımcı fonksiyonlar)
# =============================================================================

def get_ssh_security_recommendations() -> List[str]:
    """
    Genel SSH güvenlik önerilerini döndürür (her zaman geçerli).
    
    Returns:
        List[str]: SSH güvenlik en iyi uygulamaları
    
    Examples:
        >>> recommendations = get_ssh_security_recommendations()
        >>> for rec in recommendations:
        ...     print(f"  • {rec}")
    
    Note:
        Bu fonksiyon config okumadan genel öneriler verir.
        Sisteme özel analiz için audit_ssh_config() kullanın.
    """
    return [
        "🔒 SSH Güvenlik En İyi Uygulamaları:",
        "",
        "1. Root Girişi:",
        "   PermitRootLogin no",
        "   → Root kullanıcısı ile doğrudan giriş yapılamaz",
        "",
        "2. Şifre Doğrulama:",
        "   PasswordAuthentication no",
        "   → Sadece SSH key ile giriş (şifre brute-force önlenir)",
        "",
        "3. Boş Şifre (KRİTİK!):",
        "   PermitEmptyPasswords no",
        "   → Boş şifreli hesaplar giriş yapamaz",
        "",
        "4. SSH Protokol:",
        "   Protocol 2",
        "   → SSH v1 güvensiz, v2 kullanın",
        "",
        "5. Port Değiştirme:",
        "   Port 2222",
        "   → Varsayılan port (22) yerine özel port (brute-force azalır)",
        "",
        "6. X11 Forwarding:",
        "   X11Forwarding no",
        "   → Gereksizse kapatın (güvenlik riski)",
        "",
        "7. Kullanıcı Environment:",
        "   PermitUserEnvironment no",
        "   → Kullanıcı ortam değişkenleri güvenlik riski",
        "",
        "8. Giriş Denemesi Limiti:",
        "   MaxAuthTries 3",
        "   → Maksimum 3 başarısız deneme (brute-force zorlaşır)",
        "",
        "9. SSH Key Kullanımı:",
        "   ssh-keygen -t ed25519 -C 'your@email.com'",
        "   ssh-copy-id user@server",
        "",
        "10. Fail2ban:",
        "    sudo apt install fail2ban",
        "    → Otomatik IP engelleme (brute-force koruması)",
        "",
        "Yapılandırmayı Test Edin:",
        "  sudo sshd -t       # Config syntax kontrolü",
        "  sudo systemctl reload sshd  # Değişiklikleri uygula",
    ]


def get_ssh_config_template() -> str:
    """
    Güvenli SSH yapılandırma şablonu döndürür.
    
    Returns:
        str: /etc/ssh/sshd_config için güvenli şablon
    
    Examples:
        >>> template = get_ssh_config_template()
        >>> print(template)
        >>> # Dosyaya yazabilirsiniz (dikkatli olun!)
    
    Warning:
        Bu şablonu doğrudan kopyalamadan önce yedek alın!
        sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    """
    return """# =============================================================================
# Güvenli SSH Yapılandırması
# =============================================================================
# Oluşturulma: 2025-11-01
# Kaynak: linux_teknikeri.checks.security.ssh
# 
# UYARI: Bu dosyayı kullanmadan önce yedek alın!
# sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
# =============================================================================

# 1. TEMEL AYARLAR
Port 2222                      # Özel port (brute-force azalır)
Protocol 2                     # SSH v2 (güvenli)
ListenAddress 0.0.0.0          # Tüm interface'lerde dinle (veya özel IP)

# 2. KİMLİK DOĞRULAMA (ÇOK ÖNEMLİ!)
PermitRootLogin no             # Root girişi yasak
PasswordAuthentication no      # Sadece SSH key (şifre yok!)
PermitEmptyPasswords no        # Boş şifre yasak (KRİTİK!)
PubkeyAuthentication yes       # SSH key izni
MaxAuthTries 3                 # Maksimum 3 deneme

# 3. GÜVENLİK
X11Forwarding no               # X11 yönlendirme kapalı
PermitUserEnvironment no       # Kullanıcı environment kapalı
AllowTcpForwarding no          # TCP forwarding kapalı (opsiyonel)
GatewayPorts no                # Gateway port kapalı

# 4. OTURUM AYARLARI
ClientAliveInterval 300        # 5 dakika (keepalive)
ClientAliveCountMax 2          # 2 keepalive sonra disconnect
LoginGraceTime 60              # Login için 60 saniye

# 5. KULLANICI KISITLAMALARI (opsiyonel)
# AllowUsers user1 user2       # Sadece bu kullanıcılar
# AllowGroups sshusers         # Sadece bu grup
# DenyUsers baduser            # Bu kullanıcılar yasak

# 6. BANNER (opsiyonel)
# Banner /etc/ssh/ssh_banner   # Giriş mesajı

# 7. LOG AYARLARI
SyslogFacility AUTH            # Log facility
LogLevel INFO                  # Log seviyesi (verbose için DEBUG)

# 8. ŞİFRELEME
# Modern şifreleme algoritmaları (opsiyonel, OpenSSH 7.0+)
# Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com
# MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
# KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256

# =============================================================================
# NOTLAR:
# - Değişikliklerden sonra test edin: sudo sshd -t
# - Uygulamak için: sudo systemctl reload sshd
# - SSH key oluşturun: ssh-keygen -t ed25519 -C "your@email.com"
# - Key'i sunucuya kopyalayın: ssh-copy-id -i ~/.ssh/id_ed25519.pub user@server
# - PasswordAuthentication no yapmadan önce SSH key ile bağlanabildiğinizden emin olun!
# =============================================================================
"""


def quick_ssh_check() -> Dict[str, Any]:
    """
    Hızlı SSH güvenlik kontrolü (özet bilgi).
    
    audit_ssh_config()'in basitleştirilmiş versiyonu.
    Sadece en kritik bilgileri döndürür.
    
    Returns:
        Dict[str, Any]: Özet SSH güvenlik durumu
            {
                'secure': bool,              # Genel olarak güvenli mi?
                'risk_level': str,           # Risk seviyesi
                'critical_issues': List[str],# Kritik sorunlar
                'score': int,                # Güvenlik skoru (0-100)
            }
    
    Examples:
        >>> quick = quick_ssh_check()
        >>> if not quick['secure']:
        ...     print("⚠️  SSH güvensiz!")
        ...     for issue in quick['critical_issues']:
        ...         print(f"  • {issue}")
    """
    try:
        audit = audit_ssh_config()
        
        # Kritik sorunları tespit et
        critical_issues = []
        
        if audit.get('empty_passwords_permitted'):
            critical_issues.append("🔴 Boş şifre izni var!")
        
        if audit.get('root_login_permitted') and audit.get('password_auth_enabled'):
            critical_issues.append("🔴 Root + şifre girişi aktif!")
        
        if audit.get('root_login_permitted'):
            critical_issues.append("⚠️  Root girişi aktif")
        
        if audit.get('password_auth_enabled'):
            critical_issues.append("⚠️  Şifre ile giriş aktif")
        
        # SSHAudit oluştur ve skor hesapla
        ssh_obj = SSHAudit(**audit)
        score = ssh_obj.get_security_score()
        
        return {
            'secure': ssh_obj.is_secure(),
            'risk_level': audit['risk_level'],
            'critical_issues': critical_issues,
            'score': score,
        }
    
    except Exception as e:
        log.error(f"Hızlı SSH kontrolü başarısız: {e}")
        return {
            'secure': None,
            'risk_level': 'UNKNOWN',
            'critical_issues': [f"Kontrol edilemedi: {str(e)}"],
            'score': 0,
        }


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

log.debug(f"SSH modülü yüklendi (v{__version__}, {len(SSH_CONFIG_RULES)} kural)")