"""
SSH Yapılandırma Kuralları
===========================

SSH config ayarlarını kontrol eden kural tanımları.

Bu modül rule-based architecture ile SSH güvenlik denetimini sağlar.
Her kural bir SSH ayarını temsil eder ve:
    - Regex pattern (config'den parse için)
    - Field name (SSHAudit dataclass'ındaki alan)
    - Parser fonksiyon (string → uygun tip)
    - Validator fonksiyon (değer + audit → öneri)
    - Varsayılan değer (opsiyonel)
    - Zorunluluk durumu (opsiyonel)

Dataclass:
    SSHConfigRule - Tek bir SSH kural tanımı

Kural Listesi:
    SSH_CONFIG_RULES - Tüm SSH kurallarının listesi (8 kural)

Rule-Based Architecture Avantajları:
    ✅ Yeni kural eklemek kolay (sadece listeye ekle)
    ✅ Kurallar bağımsız (bakım kolay)
    ✅ Test edilebilir (her kural ayrı test)
    ✅ Dokümante (kural tanımı = dokümantasyon)
    ✅ Genişletilebilir (custom kurallar eklenebilir)

Örnekler:
    >>> from linux_teknikeri.checks.security.ssh import SSH_CONFIG_RULES
    >>> 
    >>> # Tüm kuralları listele
    >>> for rule in SSH_CONFIG_RULES:
    ...     print(f"{rule.name}: {rule.field_name}")
    PermitRootLogin: root_login_permitted
    PasswordAuthentication: password_auth_enabled
    ...
    >>> 
    >>> # İlk kural
    >>> root_rule = SSH_CONFIG_RULES[0]
    >>> print(root_rule.name)
    PermitRootLogin
    >>> 
    >>> # Config parse et
    >>> import re
    >>> config = "PermitRootLogin yes\\n"
    >>> match = re.search(root_rule.pattern, config, re.MULTILINE)
    >>> if match:
    ...     value = root_rule.parser(match.group(1))  # True
    ...     print(f"Parsed: {value}")
    Parsed: True
    >>> 
    >>> # Validate et
    >>> from linux_teknikeri.checks.security import SSHAudit
    >>> audit = SSHAudit(config_exists=True, port='22')
    >>> recommendation = root_rule.validator(value, audit)
    >>> print(recommendation)
    🔴 CRİTİK: Root girişi aktif! Düzeltin: PermitRootLogin no

See Also:
    - validators.py: Validator fonksiyonları
    - audit.py: Kuralları kullanan denetim fonksiyonu
    - SSHAudit: Denetim sonuç dataclass'ı

Author: ozturu68
Version: 0.5.0
Date: 2025-11-01
License: MIT
"""

import logging
from dataclasses import dataclass
from typing import Callable, Optional, Any, List

# Local imports
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
from ..models import SSHAudit

# Logger
log = logging.getLogger(__name__)


# =============================================================================
# SSH CONFIG RULE DATACLASS
# =============================================================================

@dataclass
class SSHConfigRule:
    """
    SSH yapılandırma kuralı tanımı.
    
    Her kural bir SSH ayarını kontrol eder ve güvenlik önerisi üretir.
    Rule-based architecture sayesinde yeni kurallar kolayca eklenebilir.
    
    Attributes:
        name (str): SSH ayar adı (config dosyasındaki isim)
            Örnek: "PermitRootLogin", "Port", "Protocol"
        
        pattern (str): Regex pattern (config dosyasından parse için)
            Örnek: r'^\s*PermitRootLogin\s+(\w+)'
            Not: MULTILINE ve IGNORECASE flag'leri ile kullanılır
        
        field_name (str): SSHAudit dataclass'ındaki field adı
            Örnek: "root_login_permitted", "port", "ssh_protocol"
        
        parser (Callable[[str], Any]): Parse fonksiyonu
            String değeri uygun tipe çevirir
            Örnek: lambda v: v.lower() == 'yes'  # str → bool
            Örnek: lambda v: int(v)              # str → int
        
        validator (Callable[[Any, SSHAudit], Optional[str]]): Validator fonksiyon
            Parse edilen değeri kontrol eder ve öneri döndürür
            Signature: (value, audit) → Optional[str]
            None: Güvenli (öneri yok)
            str: Güvenlik önerisi
        
        is_required (bool): Zorunlu ayar mı?
            True: Bu ayar None olmamalı (eksikse uyarı)
            False: Opsiyonel (None olabilir)
            Default: False
        
        default_value (Optional[Any]): Varsayılan değer
            Config'de yoksa kullanılır
            None: Varsayılan yok
            Default: None
    
    Examples:
        >>> # Basit kural tanımı
        >>> rule = SSHConfigRule(
        ...     name="PermitRootLogin",
        ...     pattern=r'^\s*PermitRootLogin\s+(\w+)',
        ...     field_name="root_login_permitted",
        ...     parser=lambda v: v.lower() == 'yes',
        ...     validator=_validate_root_login
        ... )
        >>> 
        >>> # Varsayılan değerli kural
        >>> port_rule = SSHConfigRule(
        ...     name="Port",
        ...     pattern=r'^\s*Port\s+(\d+)',
        ...     field_name="port",
        ...     parser=lambda v: v,
        ...     validator=_validate_port,
        ...     default_value="22"
        ... )
        >>> 
        >>> # Zorunlu kural
        >>> critical_rule = SSHConfigRule(
        ...     name="PermitEmptyPasswords",
        ...     pattern=r'^\s*PermitEmptyPasswords\s+(\w+)',
        ...     field_name="empty_passwords_permitted",
        ...     parser=lambda v: v.lower() == 'yes',
        ...     validator=_validate_empty_passwords,
        ...     is_required=True  # Bu KRİTİK!
        ... )
    
    Usage Flow:
        1. Config dosyası okunur
        2. Pattern ile regex match yapılır
        3. Match bulunursa parser ile parse edilir
        4. Parse edilen değer SSHAudit'e atanır
        5. Validator ile kontrol edilir
        6. Öneri üretilirse listeye eklenir
    
    Note:
        - Tüm pattern'ler case-insensitive (IGNORECASE)
        - Tüm pattern'ler multiline (MULTILINE)
        - Parser fonksiyonları exception raise edebilir (handle edilir)
        - Validator fonksiyonları pure function olmalı (side-effect yok)
    
    See Also:
        - SSH_CONFIG_RULES: Tüm kuralların listesi
        - _parse_ssh_setting(): Pattern matching ve parsing
        - _apply_ssh_rules(): Kuralları uygulama
    """
    
    name: str
    pattern: str
    field_name: str
    parser: Callable[[str], Any]
    validator: Callable[[Any, SSHAudit], Optional[str]]
    is_required: bool = False
    default_value: Optional[Any] = None
    
    def __repr__(self) -> str:
        """Developer-friendly representation."""
        return (
            f"SSHConfigRule(name='{self.name}', "
            f"field='{self.field_name}', "
            f"required={self.is_required})"
        )
    
    def __str__(self) -> str:
        """User-friendly representation."""
        return f"{self.name} → {self.field_name}"


# =============================================================================
# SSH CONFIGURATION RULES (8 kuralın tanımı)
# =============================================================================

SSH_CONFIG_RULES: List[SSHConfigRule] = [
    # =========================================================================
    # 1. PermitRootLogin (KRİTİK!)
    # =========================================================================
    SSHConfigRule(
        name="PermitRootLogin",
        pattern=r'^\s*PermitRootLogin\s+(\w+)',
        field_name="root_login_permitted",
        parser=lambda v: v.lower() == 'yes',
        validator=_validate_root_login,
        is_required=False,
        default_value=None,
    ),
    
    # =========================================================================
    # 2. PasswordAuthentication
    # =========================================================================
    SSHConfigRule(
        name="PasswordAuthentication",
        pattern=r'^\s*PasswordAuthentication\s+(\w+)',
        field_name="password_auth_enabled",
        parser=lambda v: v.lower() == 'yes',
        validator=_validate_password_auth,
        is_required=False,
        default_value=None,
    ),
    
    # =========================================================================
    # 3. PermitEmptyPasswords (ÇOK KRİTİK!)
    # =========================================================================
    SSHConfigRule(
        name="PermitEmptyPasswords",
        pattern=r'^\s*PermitEmptyPasswords\s+(\w+)',
        field_name="empty_passwords_permitted",
        parser=lambda v: v.lower() == 'yes',
        validator=_validate_empty_passwords,
        is_required=True,  # Bu KRİTİK! None olmamalı
        default_value=False,  # Varsayılan: no (güvenli)
    ),
    
    # =========================================================================
    # 4. Protocol
    # =========================================================================
    SSHConfigRule(
        name="Protocol",
        pattern=r'^\s*Protocol\s+(\S+)',
        field_name="ssh_protocol",
        parser=lambda v: v,  # String olarak sakla
        validator=_validate_protocol,
        is_required=False,
        default_value="2",  # Varsayılan: Protocol 2
    ),
    
    # =========================================================================
    # 5. Port
    # =========================================================================
    SSHConfigRule(
        name="Port",
        pattern=r'^\s*Port\s+(\d+)',
        field_name="port",
        parser=lambda v: v,  # String olarak sakla
        validator=_validate_port,
        is_required=False,
        default_value="22",  # Varsayılan: Port 22
    ),
    
    # =========================================================================
    # 6. X11Forwarding
    # =========================================================================
    SSHConfigRule(
        name="X11Forwarding",
        pattern=r'^\s*X11Forwarding\s+(\w+)',
        field_name="x11_forwarding",
        parser=lambda v: v.lower() == 'yes',
        validator=_validate_x11_forwarding,
        is_required=False,
        default_value=False,  # Varsayılan: no
    ),
    
    # =========================================================================
    # 7. PermitUserEnvironment
    # =========================================================================
    SSHConfigRule(
        name="PermitUserEnvironment",
        pattern=r'^\s*PermitUserEnvironment\s+(\w+)',
        field_name="permit_user_environment",
        parser=lambda v: v.lower() == 'yes',
        validator=_validate_user_environment,
        is_required=False,
        default_value=False,  # Varsayılan: no
    ),
    
    # =========================================================================
    # 8. MaxAuthTries
    # =========================================================================
    SSHConfigRule(
        name="MaxAuthTries",
        pattern=r'^\s*MaxAuthTries\s+(\d+)',
        field_name="max_auth_tries",
        parser=lambda v: int(v),
        validator=_validate_max_auth_tries,
        is_required=False,
        default_value=6,  # Varsayılan: 6
    ),
]


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def get_rule_by_name(name: str) -> Optional[SSHConfigRule]:
    """
    İsme göre kural bulur.
    
    Args:
        name: SSH ayar adı (örn: "PermitRootLogin")
    
    Returns:
        Optional[SSHConfigRule]: Bulunan kural veya None
    
    Examples:
        >>> rule = get_rule_by_name("PermitRootLogin")
        >>> if rule:
        ...     print(rule.field_name)
        root_login_permitted
    """
    for rule in SSH_CONFIG_RULES:
        if rule.name == name:
            return rule
    return None


def get_rule_by_field(field_name: str) -> Optional[SSHConfigRule]:
    """
    Field name'e göre kural bulur.
    
    Args:
        field_name: SSHAudit field adı (örn: "root_login_permitted")
    
    Returns:
        Optional[SSHConfigRule]: Bulunan kural veya None
    
    Examples:
        >>> rule = get_rule_by_field("root_login_permitted")
        >>> if rule:
        ...     print(rule.name)
        PermitRootLogin
    """
    for rule in SSH_CONFIG_RULES:
        if rule.field_name == field_name:
            return rule
    return None


def get_critical_rules() -> List[SSHConfigRule]:
    """
    Kritik (zorunlu) kuralları döndürür.
    
    Returns:
        List[SSHConfigRule]: Kritik kurallar (is_required=True)
    
    Examples:
        >>> critical = get_critical_rules()
        >>> for rule in critical:
        ...     print(f"KRİTİK: {rule.name}")
        KRİTİK: PermitEmptyPasswords
    """
    return [rule for rule in SSH_CONFIG_RULES if rule.is_required]


def get_rules_with_defaults() -> List[SSHConfigRule]:
    """
    Varsayılan değeri olan kuralları döndürür.
    
    Returns:
        List[SSHConfigRule]: Varsayılan değerli kurallar
    
    Examples:
        >>> defaults = get_rules_with_defaults()
        >>> for rule in defaults:
        ...     print(f"{rule.name} = {rule.default_value}")
        PermitEmptyPasswords = False
        Protocol = 2
        Port = 22
        X11Forwarding = False
        PermitUserEnvironment = False
        MaxAuthTries = 6
    """
    return [rule for rule in SSH_CONFIG_RULES if rule.default_value is not None]


def validate_rules_consistency() -> List[str]:
    """
    Kural tanımlarının tutarlılığını kontrol eder (self-check).
    
    Returns:
        List[str]: Hata mesajları (boşsa tutarlı)
    
    Examples:
        >>> errors = validate_rules_consistency()
        >>> if errors:
        ...     for error in errors:
        ...         print(f"HATA: {error}")
        >>> else:
        ...     print("✅ Tüm kurallar tutarlı")
    
    Note:
        Bu fonksiyon test ve debug için kullanılır.
        Production'da çağrılmaz.
    """
    errors = []
    
    # 1. Duplicate name kontrolü
    names = [rule.name for rule in SSH_CONFIG_RULES]
    duplicates = [name for name in names if names.count(name) > 1]
    if duplicates:
        errors.append(f"Duplicate rule names: {set(duplicates)}")
    
    # 2. Duplicate field_name kontrolü
    fields = [rule.field_name for rule in SSH_CONFIG_RULES]
    duplicates = [field for field in fields if fields.count(field) > 1]
    if duplicates:
        errors.append(f"Duplicate field names: {set(duplicates)}")
    
    # 3. Parser callable kontrolü
    for rule in SSH_CONFIG_RULES:
        if not callable(rule.parser):
            errors.append(f"{rule.name}: parser is not callable")
    
    # 4. Validator callable kontrolü
    for rule in SSH_CONFIG_RULES:
        if not callable(rule.validator):
            errors.append(f"{rule.name}: validator is not callable")
    
    # 5. Pattern geçerlilik kontrolü
    import re
    for rule in SSH_CONFIG_RULES:
        try:
            re.compile(rule.pattern)
        except re.error as e:
            errors.append(f"{rule.name}: invalid regex pattern - {e}")
    
    return errors


def get_rules_summary() -> str:
    """
    Tüm kuralların özetini metin olarak döndürür.
    
    Returns:
        str: Kural özeti (çok satırlı)
    
    Examples:
        >>> summary = get_rules_summary()
        >>> print(summary)
        SSH Configuration Rules Summary
        ================================
        Total Rules: 8
        Critical Rules: 1
        ...
    """
    lines = [
        "SSH Configuration Rules Summary",
        "=" * 50,
        f"Total Rules: {len(SSH_CONFIG_RULES)}",
        f"Critical Rules: {len(get_critical_rules())}",
        f"Rules with Defaults: {len(get_rules_with_defaults())}",
        "",
        "Rules:",
    ]
    
    for i, rule in enumerate(SSH_CONFIG_RULES, 1):
        required_mark = " (REQUIRED)" if rule.is_required else ""
        default_mark = f" [default: {rule.default_value}]" if rule.default_value is not None else ""
        lines.append(
            f"  {i}. {rule.name}{required_mark}{default_mark}"
        )
        lines.append(f"     → {rule.field_name}")
    
    return "\n".join(lines)


# =============================================================================
# MODULE INITIALIZATION
# =============================================================================

# Startup'ta kural tutarlılığını kontrol et
_consistency_errors = validate_rules_consistency()
if _consistency_errors:
    log.error(f"SSH kurallarında tutarsızlık bulundu: {_consistency_errors}")
    raise ValueError(f"SSH rule configuration errors: {_consistency_errors}")
else:
    log.debug(f"SSH kuralları yüklendi: {len(SSH_CONFIG_RULES)} kural, tutarlı")


# =============================================================================
# MODULE METADATA
# =============================================================================

__all__ = [
    'SSHConfigRule',
    'SSH_CONFIG_RULES',
    'get_rule_by_name',
    'get_rule_by_field',
    'get_critical_rules',
    'get_rules_with_defaults',
    'validate_rules_consistency',
    'get_rules_summary',
]