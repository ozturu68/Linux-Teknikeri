"""
SSH Yapılandırma Validator Fonksiyonları
=========================================

SSH config ayarlarını validate eden fonksiyonlar.

Her validator fonksiyonu bir SSH ayarını kontrol eder ve güvenlik önerisi
döndürür. Fonksiyonlar rule-based architecture ile SSH kurallarında kullanılır.

Validator Fonksiyonları:
    _validate_root_login()         - PermitRootLogin ayarı
    _validate_password_auth()      - PasswordAuthentication ayarı
    _validate_empty_passwords()    - PermitEmptyPasswords ayarı (KRİTİK!)
    _validate_protocol()           - Protocol ayarı
    _validate_port()               - Port ayarı
    _validate_x11_forwarding()     - X11Forwarding ayarı
    _validate_user_environment()   - PermitUserEnvironment ayarı
    _validate_max_auth_tries()     - MaxAuthTries ayarı

Validator Signature:
    def _validate_<setting>(
        value: Optional[Type],
        audit: SSHAudit
    ) -> Optional[str]:
        ...

Args:
    value: Parse edilen ayar değeri (None olabilir)
    audit: SSH audit sonucu (kontekst bilgisi için)

Returns:
    Optional[str]: Öneri mesajı (sorun varsa) veya None (güvenli ise)

Örnekler:
    >>> from linux_teknikeri.checks.security import SSHAudit
    >>> 
    >>> # Validator kullanımı
    >>> audit = SSHAudit(config_exists=True, port='22')
    >>> 
    >>> # Root login validator
    >>> msg = _validate_root_login(True, audit)
    >>> print(msg)
    🔴 CRİTİK: Root girişi aktif! Düzeltin: PermitRootLogin no
    >>> 
    >>> # Güvenli yapılandırma
    >>> msg = _validate_root_login(False, audit)
    >>> print(msg)
    None  # Güvenli, öneri yok

Notlar:
    - Tüm validator'lar Optional değer kabul eder (ayar belirtilmemiş olabilir)
    - None değeri genellikle "ayar yok" anlamına gelir
    - Emoji kullanımı: 🔴 (kritik), ⚠️ (uyarı), 💡 (bilgi), ℹ️ (info)
    - Validator'lar pure function'dır (side-effect yok)

See Also:
    - SSHConfigRule: Validator'ları kullanan kural dataclass'ı
    - SSH_CONFIG_RULES: Tüm kurallar listesi
    - audit_ssh_config(): Ana denetim fonksiyonu

Author: ozturu68
Version: 0.5.0
Date: 2025-11-01
License: MIT
"""

import logging
from typing import Optional

# Local imports
from ..models import SSHAudit

# Logger
log = logging.getLogger(__name__)


# =============================================================================
# VALIDATOR: PermitRootLogin
# =============================================================================

def _validate_root_login(value: Optional[bool], audit: SSHAudit) -> Optional[str]:
    """
    PermitRootLogin ayarını validate eder.
    
    Root kullanıcısı ile doğrudan SSH girişi güvenlik riski oluşturur.
    En iyi uygulama: PermitRootLogin no
    
    Args:
        value: Root login izni
            - True: yes (root girebilir - GÜVENSİZ!)
            - False: no (root giremez - GÜVENLİ)
            - None: Belirtilmemiş (varsayılan: prohibit-password)
        audit: SSH audit sonucu (kontekst için)
    
    Returns:
        Optional[str]: Öneri mesajı (sorun varsa), None (güvenli ise)
    
    Risk Analizi:
        - value == True: 🔴 KRİTİK (root + şifre = brute-force hedefi)
        - value == False: ✅ Güvenli
        - value == None: ⚠️ Varsayılan davranış (key-only)
    
    Examples:
        >>> audit = SSHAudit(config_exists=True, port='22')
        >>> 
        >>> # Root aktif (GÜVENSİZ)
        >>> msg = _validate_root_login(True, audit)
        >>> assert "CRİTİK" in msg
        >>> 
        >>> # Root kapalı (GÜVENLİ)
        >>> msg = _validate_root_login(False, audit)
        >>> assert msg is None
        >>> 
        >>> # Belirtilmemiş (varsayılan)
        >>> msg = _validate_root_login(None, audit)
        >>> assert "belirtilmemiş" in msg
    
    SSH Config:
        # Güvensiz (brute-force hedefi)
        PermitRootLogin yes
        
        # Güvenli (SSH key ile root giriş)
        PermitRootLogin prohibit-password
        PermitRootLogin without-password
        
        # En güvenli (root hiç giremez)
        PermitRootLogin no
    
    Note:
        - Ubuntu/Debian varsayılan: prohibit-password (key-only)
        - Bazı sistemler varsayılan: yes (GÜVENSİZ!)
        - Production'da her zaman "no" kullanın
    """
    if value is True:
        # Root + şifre = brute-force hedefi
        log.warning("SSH: Root girişi aktif (GÜVENSİZ!)")
        return (
            "🔴 CRİTİK: Root girişi aktif! "
            "Root kullanıcısı doğrudan giriş yapabilir (brute-force hedefi).\n"
            "Düzeltme: PermitRootLogin no"
        )
    elif value is False:
        # En güvenli
        log.debug("SSH: Root girişi kapalı (GÜVENLİ)")
        return None  # Güvenli, öneri yok
    elif value is None:
        # Ayar belirtilmemiş, varsayılan davranış
        log.info("SSH: PermitRootLogin ayarı belirtilmemiş (varsayılan)")
        return (
            "ℹ️  PermitRootLogin ayarı açıkça belirtilmemiş. "
            "Varsayılan davranış: prohibit-password (sadece SSH key ile root giriş).\n"
            "Daha güvenli: PermitRootLogin no"
        )
    else:
        # without-password veya prohibit-password gibi değerler
        # Bu değerler boolean parse edilmemiş, string olarak gelmiş
        log.debug(f"SSH: PermitRootLogin = {value} (key-only)")
        return (
            "💡 Root sadece SSH key ile girebiliyor (iyi). "
            "Daha güvenli: PermitRootLogin no"
        )


# =============================================================================
# VALIDATOR: PasswordAuthentication
# =============================================================================

def _validate_password_auth(value: Optional[bool], audit: SSHAudit) -> Optional[str]:
    """
    PasswordAuthentication ayarını validate eder.
    
    Şifre ile giriş brute-force saldırılarına açıktır.
    En iyi uygulama: PasswordAuthentication no (sadece SSH key)
    
    Args:
        value: Şifre ile giriş izni
            - True: yes (şifre ile giriş - GÜVENSİZ!)
            - False: no (sadece SSH key - GÜVENLİ)
            - None: Belirtilmemiş (varsayılan: yes - GÜVENSİZ!)
        audit: SSH audit sonucu
    
    Returns:
        Optional[str]: Öneri mesajı
    
    Examples:
        >>> # Şifre aktif (GÜVENSİZ)
        >>> msg = _validate_password_auth(True, audit)
        >>> assert "Şifre ile giriş aktif" in msg
        >>> 
        >>> # SSH key only (GÜVENLİ)
        >>> msg = _validate_password_auth(False, audit)
        >>> assert msg is None
    
    SSH Config:
        # Güvensiz (brute-force riski)
        PasswordAuthentication yes
        
        # Güvenli (sadece SSH key)
        PasswordAuthentication no
    
    Note:
        Varsayılan değer genellikle "yes" (GÜVENSİZ!)
        SSH key kullanımı için:
            1. ssh-keygen -t ed25519 -C "your@email.com"
            2. ssh-copy-id user@server
            3. PasswordAuthentication no
    """
    if value is True:
        log.warning("SSH: Şifre ile giriş aktif (brute-force riski)")
        return (
            "⚠️  Şifre ile giriş aktif (brute-force riski). "
            "Sadece SSH key kullanın.\n"
            "Düzeltme: PasswordAuthentication no\n"
            "SSH key oluştur: ssh-keygen -t ed25519 -C 'your@email.com'\n"
            "Key'i kopyala: ssh-copy-id user@server"
        )
    elif value is False:
        log.debug("SSH: Şifre ile giriş kapalı (GÜVENLİ)")
        return None  # Güvenli
    elif value is None:
        # Belirtilmemiş, varsayılan "yes" (GÜVENSİZ!)
        log.warning("SSH: PasswordAuthentication belirtilmemiş (varsayılan: yes)")
        return (
            "⚠️  PasswordAuthentication ayarı belirtilmemiş. "
            "Varsayılan: yes (şifre ile giriş aktif - GÜVENSİZ!).\n"
            "Düzeltme: PasswordAuthentication no"
        )
    
    return None


# =============================================================================
# VALIDATOR: PermitEmptyPasswords (ÇOK KRİTİK!)
# =============================================================================

def _validate_empty_passwords(value: Optional[bool], audit: SSHAudit) -> Optional[str]:
    """
    PermitEmptyPasswords ayarını validate eder (ÇOK KRİTİK!).
    
    Boş şifreli hesaplara giriş izni ÇOK CİDDİ bir güvenlik açığıdır!
    Bu ayar MUTLAKA "no" olmalıdır.
    
    Args:
        value: Boş şifre izni
            - True: yes (🔴 FELAKET! HEMEN KAPATIN!)
            - False: no (✅ GÜVENLİ)
            - None: Belirtilmemiş (varsayılan: no - GÜVENLİ)
        audit: SSH audit sonucu
    
    Returns:
        Optional[str]: Öneri mesajı
    
    Risk Analizi:
        value == True: 🔴🔴🔴 CRITICAL RISK (acil müdahale!)
            - Boş şifreli hesaplar SSH ile giriş yapabilir
            - Sistemin tamamen açık olması gibi
            - HEMEN KAPATIN!
    
    Examples:
        >>> # Boş şifre izni (FELAKET!)
        >>> msg = _validate_empty_passwords(True, audit)
        >>> assert "CRİTİK" in msg and "HEMEN" in msg
        >>> 
        >>> # Boş şifre yasak (GÜVENLİ)
        >>> msg = _validate_empty_passwords(False, audit)
        >>> assert msg is None
    
    SSH Config:
        # 🔴 FELAKET! ASLA YAPMAYIN!
        PermitEmptyPasswords yes
        
        # ✅ MUTLAKA BU OLMALI
        PermitEmptyPasswords no
    
    Note:
        Bu ayar True ise SSH risk seviyesi CRITICAL'dir!
        Otomatik olarak en yüksek öncelikli uyarı üretilir.
    """
    if value is True:
        # 🔴🔴🔴 CRITICAL!
        log.error("SSH: Boş şifre izni aktif! CRİTİK GÜVENLİK AÇIĞI!")
        return (
            "🔴🔴🔴 ÇOK KRİTİK: Boş şifreler kabul ediliyor! 🔴🔴🔴\n"
            "Boş şifreli hesaplar SSH ile giriş yapabilir (FELAKET!).\n"
            "Sistem tamamen açık sayılır!\n"
            "⚡ HEMEN KAPATIN: PermitEmptyPasswords no\n"
            "⚡ sudo systemctl reload sshd"
        )
    elif value is False:
        log.debug("SSH: Boş şifre izni kapalı (GÜVENLİ)")
        return None  # Güvenli
    elif value is None:
        # Belirtilmemiş, varsayılan "no" (GÜVENLİ)
        log.debug("SSH: PermitEmptyPasswords belirtilmemiş (varsayılan: no)")
        return None  # Varsayılan güvenli
    
    return None


# =============================================================================
# VALIDATOR: Protocol
# =============================================================================

def _validate_protocol(value: Optional[str], audit: SSHAudit) -> Optional[str]:
    """
    Protocol ayarını validate eder.
    
    SSH Protocol 1 eski ve güvensizdir. Sadece Protocol 2 kullanılmalıdır.
    
    Args:
        value: SSH protokol versiyonu
            - "1": SSH v1 (🔴 ÇOK ESKİ! GÜVENSİZ!)
            - "2": SSH v2 (✅ GÜVENLİ)
            - "1,2": Her ikisi (⚠️ v1 riski var)
            - None: Belirtilmemiş (varsayılan: 2 - GÜVENLİ)
        audit: SSH audit sonucu
    
    Returns:
        Optional[str]: Öneri mesajı
    
    Examples:
        >>> # SSH v1 (ESKİ VE GÜVENSİZ!)
        >>> msg = _validate_protocol("1", audit)
        >>> assert "CRİTİK" in msg
        >>> 
        >>> # SSH v2 (GÜVENLİ)
        >>> msg = _validate_protocol("2", audit)
        >>> assert msg is None
    
    SSH Config:
        # 🔴 Eski ve güvensiz
        Protocol 1
        
        # ✅ Modern ve güvenli
        Protocol 2
        
        # ⚠️ Her ikisi (v1 riski var)
        Protocol 1,2
    
    Note:
        - SSH v1: 1995 (eski, güvensiz, deprecated)
        - SSH v2: 2006 (modern, güvenli, RFC 4253)
        - Modern SSH sunucuları sadece v2 destekler
    """
    if value == '1':
        log.error("SSH: Protocol 1 kullanılıyor (ESKİ VE GÜVENSİZ!)")
        return (
            "🔴 CRİTİK: SSH Protocol 1 kullanılıyor! "
            "SSH v1 eski ve güvensiz (1995, deprecated).\n"
            "Düzeltme: Protocol 2\n"
            "Not: Modern SSH sunucuları zaten sadece v2 destekler."
        )
    elif value and '1' in value:
        # "1,2" gibi
        log.warning("SSH: Protocol 1 destekleniyor (risk var)")
        return (
            "⚠️  SSH Protocol 1 destekleniyor (güvensiz). "
            "Sadece Protocol 2 kullanın.\n"
            "Düzeltme: Protocol 2"
        )
    elif value == '2':
        log.debug("SSH: Protocol 2 kullanılıyor (GÜVENLİ)")
        return None  # Güvenli
    elif value is None:
        # Varsayılan Protocol 2 (GÜVENLİ)
        log.debug("SSH: Protocol belirtilmemiş (varsayılan: 2)")
        return None  # Varsayılan güvenli
    
    return None


# =============================================================================
# VALIDATOR: Port
# =============================================================================

def _validate_port(value: Optional[str], audit: SSHAudit) -> Optional[str]:
    """
    Port ayarını validate eder.
    
    Varsayılan SSH port'u (22) brute-force saldırılarının ana hedefidir.
    Özel port kullanımı saldırıları önemli ölçüde azaltır.
    
    Args:
        value: SSH port numarası
            - "22": Varsayılan port (⚠️ brute-force hedefi)
            - "2222": Özel port (💡 önerilir)
            - None: Belirtilmemiş (varsayılan: 22)
        audit: SSH audit sonucu
    
    Returns:
        Optional[str]: Öneri mesajı
    
    Examples:
        >>> # Varsayılan port (brute-force hedefi)
        >>> msg = _validate_port("22", audit)
        >>> assert "varsayılan port" in msg
        >>> 
        >>> # Özel port (iyi)
        >>> msg = _validate_port("2222", audit)
        >>> assert msg is None
    
    SSH Config:
        # ⚠️ Varsayılan (brute-force hedefi)
        Port 22
        
        # 💡 Özel port (önerilir)
        Port 2222
        Port 2200
    
    Note:
        - Port değiştirme "security by obscurity" değildir
        - Ama brute-force otomasyonlarını %90+ azaltır
        - 1024'ten büyük port seçin (privileged port değil)
        - Client'larda: ssh -p 2222 user@server
    """
    if value == '22':
        log.info("SSH: Varsayılan port (22) kullanılıyor")
        return (
            "💡 SSH varsayılan port (22) kullanılıyor. "
            "Özel port (ör: 2222) brute-force saldırılarını %90+ azaltır.\n"
            "Düzeltme: Port 2222\n"
            "Client bağlantı: ssh -p 2222 user@server\n"
            "Firewall: sudo ufw allow 2222/tcp"
        )
    elif value is None:
        # Varsayılan 22
        log.info("SSH: Port belirtilmemiş (varsayılan: 22)")
        return (
            "💡 SSH port belirtilmemiş (varsayılan: 22). "
            "Özel port kullanımı önerilir.\n"
            "Düzeltme: Port 2222"
        )
    else:
        # Özel port kullanılıyor
        log.debug(f"SSH: Özel port kullanılıyor ({value})")
        return None  # İyi
    
    return None


# =============================================================================
# VALIDATOR: X11Forwarding
# =============================================================================

def _validate_x11_forwarding(value: Optional[bool], audit: SSHAudit) -> Optional[str]:
    """
    X11Forwarding ayarını validate eder.
    
    X11 forwarding GUI uygulamaları için kullanılır ama güvenlik riski oluşturur.
    Gereksizse kapatılmalıdır.
    
    Args:
        value: X11 forwarding izni
            - True: yes (⚠️ güvenlik riski)
            - False: no (✅ güvenli)
            - None: Belirtilmemiş (varsayılan: no - GÜVENLİ)
        audit: SSH audit sonucu
    
    Returns:
        Optional[str]: Öneri mesajı
    
    Examples:
        >>> # X11 aktif (risk)
        >>> msg = _validate_x11_forwarding(True, audit)
        >>> assert "güvenlik riski" in msg
        >>> 
        >>> # X11 kapalı (güvenli)
        >>> msg = _validate_x11_forwarding(False, audit)
        >>> assert msg is None
    
    SSH Config:
        # ⚠️ Güvenlik riski
        X11Forwarding yes
        
        # ✅ Güvenli
        X11Forwarding no
    
    Note:
        - X11 forwarding: GUI uygulamaları uzaktan çalıştırır
        - Gereksizse kapatın (güvenlik riski)
        - Server'da GUI yoksa zaten gereksiz
    """
    if value is True:
        log.warning("SSH: X11 Forwarding aktif (güvenlik riski)")
        return (
            "⚠️  X11 Forwarding aktif (güvenlik riski). "
            "GUI uygulamaları gerekmedikçe kapatın.\n"
            "Düzeltme: X11Forwarding no"
        )
    elif value is False:
        log.debug("SSH: X11 Forwarding kapalı (GÜVENLİ)")
        return None  # Güvenli
    elif value is None:
        # Varsayılan "no" (GÜVENLİ)
        log.debug("SSH: X11Forwarding belirtilmemiş (varsayılan: no)")
        return None  # Varsayılan güvenli
    
    return None


# =============================================================================
# VALIDATOR: PermitUserEnvironment
# =============================================================================

def _validate_user_environment(value: Optional[bool], audit: SSHAudit) -> Optional[str]:
    """
    PermitUserEnvironment ayarını validate eder.
    
    Kullanıcı ortam değişkenleri güvenlik açığı oluşturabilir (LD_PRELOAD vb.).
    Gereksizse kapatılmalıdır.
    
    Args:
        value: Kullanıcı environment izni
            - True: yes (⚠️ güvenlik riski)
            - False: no (✅ güvenli)
            - None: Belirtilmemiş (varsayılan: no - GÜVENLİ)
        audit: SSH audit sonucu
    
    Returns:
        Optional[str]: Öneri mesajı
    
    Examples:
        >>> # User environment aktif (risk)
        >>> msg = _validate_user_environment(True, audit)
        >>> assert "güvenlik riski" in msg
        >>> 
        >>> # User environment kapalı (güvenli)
        >>> msg = _validate_user_environment(False, audit)
        >>> assert msg is None
    
    SSH Config:
        # ⚠️ Güvenlik riski
        PermitUserEnvironment yes
        
        # ✅ Güvenli
        PermitUserEnvironment no
    
    Note:
        - ~/.ssh/environment dosyası ile ortam değişkenleri set edilebilir
        - LD_PRELOAD gibi değişkenlerle privilege escalation riski
        - Özel use-case yoksa kapatın
    """
    if value is True:
        log.warning("SSH: PermitUserEnvironment aktif (güvenlik riski)")
        return (
            "⚠️  PermitUserEnvironment aktif (güvenlik riski). "
            "Kullanıcı ortam değişkenleri privilege escalation riski oluşturabilir.\n"
            "Düzeltme: PermitUserEnvironment no"
        )
    elif value is False:
        log.debug("SSH: PermitUserEnvironment kapalı (GÜVENLİ)")
        return None  # Güvenli
    elif value is None:
        # Varsayılan "no" (GÜVENLİ)
        log.debug("SSH: PermitUserEnvironment belirtilmemiş (varsayılan: no)")
        return None  # Varsayılan güvenli
    
    return None


# =============================================================================
# VALIDATOR: MaxAuthTries
# =============================================================================

def _validate_max_auth_tries(value: Optional[int], audit: SSHAudit) -> Optional[str]:
    """
    MaxAuthTries ayarını validate eder.
    
    Maksimum giriş denemesi sayısı brute-force saldırılarını sınırlar.
    Önerilen değer: 3
    
    Args:
        value: Maksimum giriş denemesi sayısı
            - <= 3: İyi (✅)
            - > 3: Çok yüksek (💡 azaltın)
            - None: Belirtilmemiş (varsayılan: 6)
        audit: SSH audit sonucu
    
    Returns:
        Optional[str]: Öneri mesajı
    
    Examples:
        >>> # Çok yüksek limit
        >>> msg = _validate_max_auth_tries(10, audit)
        >>> assert "çok yüksek" in msg
        >>> 
        >>> # İyi limit
        >>> msg = _validate_max_auth_tries(3, audit)
        >>> assert msg is None
    
    SSH Config:
        # ⚠️ Çok yüksek (varsayılan)
        MaxAuthTries 6
        
        # ✅ Önerilen
        MaxAuthTries 3
        
        # 🔴 Çok düşük (kullanıcı kilitlenebilir)
        MaxAuthTries 1
    
    Note:
        - Varsayılan: 6 (biraz yüksek)
        - Önerilen: 3 (brute-force'u zorlaştırır)
        - 1 yaparsanız kullanıcılar kilitlenebilir (typo)
    """
    if value is not None and value > 3:
        log.info(f"SSH: MaxAuthTries yüksek ({value})")
        return (
            f"💡 MaxAuthTries çok yüksek ({value}). "
            "Brute-force saldırılarını kolaylaştırır.\n"
            f"Düzeltme: MaxAuthTries 3\n"
            "Not: Çok düşük (1) yaparsanız kullanıcılar typo'dan kilitlenebilir."
        )
    elif value is not None and value <= 3:
        log.debug(f"SSH: MaxAuthTries iyi ({value})")
        return None  # İyi
    elif value is None:
        # Varsayılan 6 (biraz yüksek)
        log.info("SSH: MaxAuthTries belirtilmemiş (varsayılan: 6)")
        return (
            "💡 MaxAuthTries belirtilmemiş (varsayılan: 6). "
            "Daha güvenli: MaxAuthTries 3"
        )
    
    return None


# =============================================================================
# MODULE METADATA
# =============================================================================

__all__ = [
    '_validate_root_login',
    '_validate_password_auth',
    '_validate_empty_passwords',
    '_validate_protocol',
    '_validate_port',
    '_validate_x11_forwarding',
    '_validate_user_environment',
    '_validate_max_auth_tries',
]