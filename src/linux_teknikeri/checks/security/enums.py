"""
Güvenlik Modülü Enum Tanımları
===============================

Güvenlik seviyelerini ve kategorilerini tanımlayan enum sınıfları.

Enum'lar:
    SecurityLevel      - Genel sistem güvenlik seviyesi
    SSHSecurityLevel   - SSH özel güvenlik seviyesi
    FirewallStatus     - Güvenlik duvarı durumu (bonus)
    RiskCategory       - Risk kategorileri (bonus)

Type-Safety:
    Enum'lar tip güvenliği sağlar ve magic string'leri önler.
    
    Kötü:  if status == "CRITICAL":  # String, typo riski
    İyi:   if status == SecurityLevel.CRITICAL:  # Type-safe

Author: ozturu68
Version: 0.5.0
Date: 2025-11-01
License: MIT
"""

from enum import Enum, auto
from typing import Dict, Tuple


# =============================================================================
# SECURITY LEVEL (Genel Güvenlik Seviyesi)
# =============================================================================

class SecurityLevel(Enum):
    """
    Genel sistem güvenlik seviyesi kategorileri.
    
    Güvenlik skoru (0-100) beş kategoriye ayrılır.
    Her seviye farklı bir risk derecesini temsil eder.
    
    Attributes:
        EXCELLENT: 90-100 puan - Mükemmel güvenlik
        GOOD: 70-89 puan - İyi güvenlik
        FAIR: 50-69 puan - Orta düzey güvenlik
        POOR: 30-49 puan - Zayıf güvenlik
        CRITICAL: 0-29 puan - Kritik güvenlik sorunu
    
    Skor Aralıkları:
        EXCELLENT: >= 90 (Sistemde ciddi güvenlik sorunu yok)
        GOOD:      70-89 (Küçük iyileştirmeler yapılabilir)
        FAIR:      50-69 (Bazı güvenlik açıkları var)
        POOR:      30-49 (Ciddi güvenlik sorunları var)
        CRITICAL:  < 30  (Acil müdahale gerekli!)
    
    Examples:
        >>> from linux_teknikeri.checks.security import SecurityLevel
        >>> 
        >>> # Seviye kontrolü
        >>> level = SecurityLevel.GOOD
        >>> if level == SecurityLevel.CRITICAL:
        ...     print("🔴 ACİL MÜDAHALE GEREKLİ!")
        >>> 
        >>> # String karşılaştırma (name kullan)
        >>> if level.name == "GOOD":
        ...     print("✅ Güvenlik durumu iyi")
        >>> 
        >>> # Value kullanımı
        >>> print(level.value)  # "GOOD"
        >>> 
        >>> # Tüm seviyeleri listele
        >>> for lvl in SecurityLevel:
        ...     print(f"{lvl.name}: {lvl.value}")
    
    Note:
        - Enum değerleri immutable'dır (değiştirilemez)
        - Comparison: == ile karşılaştırın, is kullanmayın
        - Type-safe: Mypy ve IDE'ler anlayabilir
    
    See Also:
        - SecuritySummary.get_security_level(): Bu enum'u döndürür
        - SecuritySummary.get_security_score(): Skoru hesaplar (0-100)
    """
    
    EXCELLENT = "EXCELLENT"  # 90-100: Mükemmel
    GOOD = "GOOD"            # 70-89:  İyi
    FAIR = "FAIR"            # 50-69:  Orta
    POOR = "POOR"            # 30-49:  Zayıf
    CRITICAL = "CRITICAL"    # 0-29:   Kritik
    
    def __str__(self) -> str:
        """String representation (kullanıcı dostu)."""
        return self.value
    
    def __repr__(self) -> str:
        """Developer-friendly representation."""
        return f"<SecurityLevel.{self.name}>"
    
    @classmethod
    def from_score(cls, score: int) -> 'SecurityLevel':
        """
        Güvenlik skorundan (0-100) uygun seviyeyi belirler.
        
        Args:
            score: Güvenlik skoru (0-100)
        
        Returns:
            SecurityLevel: Uygun güvenlik seviyesi
        
        Examples:
            >>> SecurityLevel.from_score(95)
            <SecurityLevel.EXCELLENT>
            >>> 
            >>> SecurityLevel.from_score(45)
            <SecurityLevel.POOR>
            >>> 
            >>> SecurityLevel.from_score(10)
            <SecurityLevel.CRITICAL>
        
        Note:
            Negatif veya 100'den büyük skorlar geçerli aralığa çekilir.
        """
        # Skoru geçerli aralığa çek
        score = max(0, min(100, score))
        
        if score >= 90:
            return cls.EXCELLENT
        elif score >= 70:
            return cls.GOOD
        elif score >= 50:
            return cls.FAIR
        elif score >= 30:
            return cls.POOR
        else:
            return cls.CRITICAL
    
    def get_emoji(self) -> str:
        """
        Seviyeye uygun emoji döndürür.
        
        Returns:
            str: Durum emojisi
        
        Examples:
            >>> SecurityLevel.EXCELLENT.get_emoji()
            '✅'
            >>> SecurityLevel.CRITICAL.get_emoji()
            '🔴'
        """
        emoji_map = {
            self.EXCELLENT: "✅",  # Mükemmel
            self.GOOD: "🟢",       # İyi
            self.FAIR: "⚠️",        # Orta
            self.POOR: "🟠",       # Zayıf
            self.CRITICAL: "🔴",   # Kritik
        }
        return emoji_map.get(self, "❓")
    
    def get_color(self) -> str:
        """
        Terminal renk kodu döndürür (ANSI).
        
        Returns:
            str: ANSI renk kodu
        
        Examples:
            >>> level = SecurityLevel.CRITICAL
            >>> print(f"{level.get_color()}{level.value}\\033[0m")  # Kırmızı
        """
        color_map = {
            self.EXCELLENT: "\033[92m",  # Green
            self.GOOD: "\033[92m",       # Green
            self.FAIR: "\033[93m",       # Yellow
            self.POOR: "\033[91m",       # Red
            self.CRITICAL: "\033[91m",   # Red
        }
        return color_map.get(self, "\033[0m")
    
    def get_description(self) -> str:
        """
        Seviyenin açıklamasını döndürür (Türkçe).
        
        Returns:
            str: Seviye açıklaması
        
        Examples:
            >>> SecurityLevel.EXCELLENT.get_description()
            'Mükemmel güvenlik durumu - Sistemde ciddi güvenlik sorunu yok'
        """
        desc_map = {
            self.EXCELLENT: "Mükemmel güvenlik durumu - Sistemde ciddi güvenlik sorunu yok",
            self.GOOD: "İyi güvenlik durumu - Küçük iyileştirmeler yapılabilir",
            self.FAIR: "Orta düzey güvenlik - Bazı güvenlik açıkları mevcut",
            self.POOR: "Zayıf güvenlik durumu - Ciddi güvenlik sorunları var",
            self.CRITICAL: "Kritik güvenlik durumu - Acil müdahale gerekli!",
        }
        return desc_map.get(self, "Bilinmeyen güvenlik seviyesi")
    
    def needs_immediate_action(self) -> bool:
        """
        Acil eylem gerekip gerekmediğini belirtir.
        
        Returns:
            bool: CRITICAL veya POOR ise True
        
        Examples:
            >>> if SecurityLevel.CRITICAL.needs_immediate_action():
            ...     print("⚠️  ACİL EYLEM GEREKLİ!")
        """
        return self in (self.CRITICAL, self.POOR)


# =============================================================================
# SSH SECURITY LEVEL (SSH Özel Güvenlik Seviyesi)
# =============================================================================

class SSHSecurityLevel(Enum):
    """
    SSH yapılandırması özel güvenlik seviyesi.
    
    SSH güvenlik denetimi sonucunda belirlenen risk kategorisi.
    Genel SecurityLevel'dan daha detaylıdır (5 seviye).
    
    Attributes:
        CRITICAL: Boş şifre izni gibi kritik açıklar
        HIGH: Root + şifre girişi gibi ciddi sorunlar
        MEDIUM: Tek başına riskli ayarlar (root veya port 22 + şifre)
        LOW: Güvenli yapılandırma
        INFO: Bilgilendirme seviyesi (öneri)
    
    Risk Kriterleri:
        CRITICAL: - PermitEmptyPasswords = yes
        HIGH:     - PermitRootLogin = yes + PasswordAuthentication = yes
        MEDIUM:   - PermitRootLogin = yes
                  - PasswordAuthentication = yes + Port = 22
        LOW:      - Güvenli yapılandırma
        INFO:     - Bilgilendirme mesajları
    
    Examples:
        >>> from linux_teknikeri.checks.security import SSHSecurityLevel
        >>> 
        >>> # Seviye kontrolü
        >>> ssh_level = SSHSecurityLevel.HIGH
        >>> if ssh_level == SSHSecurityLevel.CRITICAL:
        ...     print("🔴 SSH KRİTİK DURUMDA!")
        >>> 
        >>> # Emoji al
        >>> print(f"{ssh_level.get_emoji()} SSH Risk: {ssh_level.value}")
        🔴 SSH Risk: HIGH
    
    Note:
        SSHAudit dataclass bu enum'u kullanır.
        Otomatik risk hesaplama __post_init__ içinde yapılır.
    
    See Also:
        - SSHAudit.risk_level: Bu enum'dan bir değer
        - audit_ssh_config(): SSH denetim fonksiyonu
    """
    
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    
    def __str__(self) -> str:
        """String representation."""
        return self.value
    
    def __repr__(self) -> str:
        """Developer-friendly representation."""
        return f"<SSHSecurityLevel.{self.name}>"
    
    def get_emoji(self) -> str:
        """
        Seviyeye uygun emoji döndürür.
        
        Returns:
            str: Risk emojisi
        """
        emoji_map = {
            self.CRITICAL: "🔴",
            self.HIGH: "🔴",
            self.MEDIUM: "⚠️",
            self.LOW: "✅",
            self.INFO: "ℹ️",
        }
        return emoji_map.get(self, "❓")
    
    def get_color(self) -> str:
        """Terminal renk kodu döndürür."""
        color_map = {
            self.CRITICAL: "\033[91m",  # Red
            self.HIGH: "\033[91m",      # Red
            self.MEDIUM: "\033[93m",    # Yellow
            self.LOW: "\033[92m",       # Green
            self.INFO: "\033[94m",      # Blue
        }
        return color_map.get(self, "\033[0m")
    
    def get_priority(self) -> int:
        """
        Öncelik seviyesi döndürür (1=en yüksek, 5=en düşük).
        
        Returns:
            int: Öncelik numarası
        
        Examples:
            >>> SSHSecurityLevel.CRITICAL.get_priority()
            1
            >>> SSHSecurityLevel.INFO.get_priority()
            5
        """
        priority_map = {
            self.CRITICAL: 1,
            self.HIGH: 2,
            self.MEDIUM: 3,
            self.LOW: 4,
            self.INFO: 5,
        }
        return priority_map.get(self, 3)
    
    def requires_immediate_fix(self) -> bool:
        """
        Acil düzeltme gerekip gerekmediğini belirtir.
        
        Returns:
            bool: CRITICAL veya HIGH ise True
        """
        return self in (self.CRITICAL, self.HIGH)


# =============================================================================
# BONUS: FIREWALL STATUS (Güvenlik Duvarı Durumu)
# =============================================================================

class FirewallStatus(Enum):
    """
    Güvenlik duvarı durum kategorileri (bonus enum).
    
    Sistemdeki güvenlik duvarı durumunu kategorize eder.
    String karşılaştırma yerine type-safe enum kullanımı sağlar.
    
    Attributes:
        ACTIVE: Güvenlik duvarı aktif ve yapılandırılmış
        INACTIVE: Güvenlik duvarı kurulu ama kapalı
        NOT_INSTALLED: Güvenlik duvarı kurulu değil
        MISCONFIGURED: Güvenlik duvarı kurulu ama yapılandırılmamış
        UNKNOWN: Durum tespit edilemedi
    
    Examples:
        >>> status = FirewallStatus.ACTIVE
        >>> if status != FirewallStatus.ACTIVE:
        ...     print("⚠️  Güvenlik duvarı aktif değil!")
    """
    
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    NOT_INSTALLED = "NOT_INSTALLED"
    MISCONFIGURED = "MISCONFIGURED"
    UNKNOWN = "UNKNOWN"
    
    def __str__(self) -> str:
        return self.value
    
    def is_secure(self) -> bool:
        """Güvenli durum mu?"""
        return self == self.ACTIVE
    
    def get_emoji(self) -> str:
        """Durum emojisi."""
        emoji_map = {
            self.ACTIVE: "✅",
            self.INACTIVE: "🔴",
            self.NOT_INSTALLED: "❌",
            self.MISCONFIGURED: "⚠️",
            self.UNKNOWN: "❓",
        }
        return emoji_map.get(self, "❓")


# =============================================================================
# BONUS: RISK CATEGORY (Risk Kategorileri)
# =============================================================================

class RiskCategory(Enum):
    """
    Güvenlik riski kategorileri (bonus enum).
    
    Güvenlik açıklarını ve riskleri kategorize etmek için kullanılır.
    
    Attributes:
        AUTHENTICATION: Kimlik doğrulama riskleri
        AUTHORIZATION: Yetkilendirme riskleri
        CONFIGURATION: Yapılandırma hataları
        NETWORK: Ağ güvenliği riskleri
        UPDATE: Güncelleme ve patch riskleri
        ENCRYPTION: Şifreleme ve veri güvenliği
        PHYSICAL: Fiziksel erişim riskleri
        SOCIAL: Sosyal mühendislik riskleri
    
    Examples:
        >>> risk = RiskCategory.AUTHENTICATION
        >>> print(f"{risk.get_emoji()} {risk.get_description()}")
        🔑 Kimlik doğrulama ve oturum yönetimi
    """
    
    AUTHENTICATION = auto()
    AUTHORIZATION = auto()
    CONFIGURATION = auto()
    NETWORK = auto()
    UPDATE = auto()
    ENCRYPTION = auto()
    PHYSICAL = auto()
    SOCIAL = auto()
    
    def get_emoji(self) -> str:
        """Kategori emojisi."""
        emoji_map = {
            self.AUTHENTICATION: "🔑",
            self.AUTHORIZATION: "🛡️",
            self.CONFIGURATION: "⚙️",
            self.NETWORK: "🌐",
            self.UPDATE: "📦",
            self.ENCRYPTION: "🔒",
            self.PHYSICAL: "🏢",
            self.SOCIAL: "👥",
        }
        return emoji_map.get(self, "❓")
    
    def get_description(self) -> str:
        """Kategori açıklaması (Türkçe)."""
        desc_map = {
            self.AUTHENTICATION: "Kimlik doğrulama ve oturum yönetimi",
            self.AUTHORIZATION: "Yetkilendirme ve erişim kontrolü",
            self.CONFIGURATION: "Sistem ve servis yapılandırması",
            self.NETWORK: "Ağ güvenliği ve firewall",
            self.UPDATE: "Güncelleme ve güvenlik yamaları",
            self.ENCRYPTION: "Şifreleme ve veri güvenliği",
            self.PHYSICAL: "Fiziksel erişim güvenliği",
            self.SOCIAL: "Sosyal mühendislik ve kullanıcı eğitimi",
        }
        return desc_map.get(self, "Bilinmeyen kategori")


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def get_all_security_levels() -> Dict[str, Tuple[str, str]]:
    """
    Tüm güvenlik seviyelerini ve açıklamalarını döndürür.
    
    Returns:
        Dict[str, Tuple[str, str]]: {level_name: (emoji, description)}
    
    Examples:
        >>> levels = get_all_security_levels()
        >>> for name, (emoji, desc) in levels.items():
        ...     print(f"{emoji} {name}: {desc}")
    """
    return {
        level.name: (level.get_emoji(), level.get_description())
        for level in SecurityLevel
    }


def get_all_ssh_levels() -> Dict[str, str]:
    """
    Tüm SSH güvenlik seviyelerini ve emoji'lerini döndürür.
    
    Returns:
        Dict[str, str]: {level_name: emoji}
    """
    return {
        level.name: level.get_emoji()
        for level in SSHSecurityLevel
    }


# =============================================================================
# MODULE METADATA
# =============================================================================

__all__ = [
    'SecurityLevel',
    'SSHSecurityLevel',
    'FirewallStatus',
    'RiskCategory',
    'get_all_security_levels',
    'get_all_ssh_levels',
]