"""
Güvenlik Modülü Veri Modelleri
===============================

Güvenlik analizi sonuçlarını tutan dataclass tanımları.

Dataclass'lar:
    SecuritySummary - Sistem güvenlik özet bilgileri
    PortInfo        - Ağ port bilgileri
    SSHAudit        - SSH yapılandırma denetim sonuçları

Type-Safety:
    Tüm modeller dataclass dekoratörü ile tanımlanmıştır.
    Type hints tam olarak belirtilmiştir (mypy uyumlu).

Immutability:
    Dataclass'lar varsayılan olarak mutable'dır.
    Immutable versiyon için frozen=True kullanılabilir.

Author: ozturu68
Version: 0.5.0
Date: 2025-11-01
License: MIT
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any
import logging

# Local imports
from .enums import SecurityLevel, SSHSecurityLevel

# Logger
log = logging.getLogger(__name__)


# =============================================================================
# SECURITY SUMMARY (Sistem Güvenlik Özeti)
# =============================================================================

@dataclass
class SecuritySummary:
    """
    Sistem güvenliği özet bilgilerini tutan veri sınıfı.
    
    Bu sınıf, sistemin genel güvenlik durumunu özetleyen metrikleri içerir.
    Güvenlik güncellemeleri, güvenlik duvarı, mandatory access control (MAC)
    sistemleri ve otomatik güncelleme yapılandırması gibi kritik bilgileri tutar.
    
    Attributes:
        security_updates_count (int): Bekleyen güvenlik güncellemesi sayısı
        firewall_status (str): Güvenlik duvarı durumu
            - "Aktif (UFW, 10 kural)"
            - "Devre Dışı (UFW)"
            - "Kurulu Değil"
            - "Yapılandırılmamış"
        apparmor_status (str): AppArmor durumu (Debian/Ubuntu)
            - "Aktif (25/30 profil enforce modda)"
            - "Yüklü Değil"
            - "Kurulu Değil"
        selinux_status (str): SELinux durumu (RHEL/CentOS)
            - "Aktif (Enforcing)"
            - "Uyarı Modu (Permissive)"
            - "Devre Dışı"
            - "Kurulu Değil (Debian/Ubuntu'da normal)"
        unattended_upgrades (str): Otomatik güncelleme yapılandırması
            - "Aktif (Güvenlik + Paket Listesi)"
            - "Aktif (Sadece Güvenlik)"
            - "Pasif"
            - "Yapılandırılmamış"
        last_update_check (str): Son güncelleme kontrolü zamanı
            - "Bugün (2025-11-01 10:30:25)"
            - "5 gün önce (2025-10-27 09:15:30)"
            - "Bilinmiyor"
        sudo_config_secure (Optional[bool]): Sudo yapılandırmasının güvenli olup olmadığı
            - True: Güvenli
            - False: Güvensiz (NOPASSWD: ALL gibi)
            - None: Kontrol edilemedi
        open_ports_count (Optional[int]): Açık port sayısı
        failed_login_attempts (Optional[int]): Başarısız giriş denemesi sayısı
        recommendations (List[str]): Güvenlik önerileri listesi
    
    Examples:
        >>> # Temel oluşturma
        >>> summary = SecuritySummary(
        ...     security_updates_count=5,
        ...     firewall_status="Aktif",
        ...     apparmor_status="Aktif",
        ...     selinux_status="Kurulu Değil",
        ...     unattended_upgrades="Aktif",
        ...     last_update_check="2 gün önce"
        ... )
        >>> 
        >>> # Öneri ekleme
        >>> summary.add_recommendation("Güvenlik güncellemesi yapın")
        >>> 
        >>> # Skor hesaplama
        >>> score = summary.get_security_score()
        >>> print(f"Güvenlik Skoru: {score}/100")
        Güvenlik Skoru: 85/100
        >>> 
        >>> # Kritik sorun kontrolü
        >>> if summary.has_critical_issues():
        ...     print("⚠️  Kritik güvenlik sorunu var!")
        >>> 
        >>> # Seviye ve emoji
        >>> level = summary.get_security_level()
        >>> emoji = summary.get_status_emoji()
        >>> print(f"{emoji} Durum: {level.value}")
        🟢 Durum: GOOD
        >>> 
        >>> # Dictionary'e çevirme
        >>> data = summary.to_dict()
        >>> print(data['security_updates_count'])
        5
    
    Note:
        - recommendations listesi otomatik olarak boş liste ile başlatılır
        - Her instance için ayrı bir liste oluşturulur (mutable default yok)
        - field(default_factory=list) kullanılarak güvenli başlatma sağlanır
    
    Thread-Safety:
        Bu sınıf thread-safe DEĞİLDİR. Multi-threading için lock kullanın.
    
    Performance:
        - to_dict() O(n) - tüm field'ları kopyalar
        - get_security_score() O(1) - basit aritmetik işlemler
        - add_recommendation() O(n) - liste taraması (duplikasyon kontrolü)
    
    See Also:
        - get_security_summary(): Bu dataclass'ı oluşturan fonksiyon
        - SecurityLevel: Güvenlik seviyesi enum'u
    """
    
    # Required fields (zorunlu)
    security_updates_count: int
    firewall_status: str
    apparmor_status: str
    selinux_status: str
    unattended_upgrades: str
    last_update_check: str
    
    # Optional fields (opsiyonel)
    sudo_config_secure: Optional[bool] = None
    open_ports_count: Optional[int] = None
    failed_login_attempts: Optional[int] = None
    
    # Mutable default (field kullanarak güvenli başlatma)
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Dataclass'ı dictionary'e çevirir.
        
        Returns:
            Dict[str, Any]: Tüm field'ları içeren dictionary
        
        Examples:
            >>> summary = SecuritySummary(...)
            >>> data = summary.to_dict()
            >>> print(data['security_updates_count'])
            5
            >>> 
            >>> # JSON serialization
            >>> import json
            >>> json_str = json.dumps(data, ensure_ascii=False)
        """
        return asdict(self)
    
    def add_recommendation(self, message: str) -> None:
        """
        Güvenlik önerisi ekler.
        
        Duplikasyon önlenir - aynı mesaj birden fazla eklenmez.
        
        Args:
            message: Eklenecek öneri mesajı
        
        Examples:
            >>> summary.add_recommendation("⚠️  Güvenlik duvarını aktif edin")
            >>> summary.add_recommendation("⚠️  Güvenlik duvarını aktif edin")  # Duplikasyon önlenir
            >>> len(summary.recommendations)
            1
        
        Note:
            Boş string eklenmez.
        """
        if message and message not in self.recommendations:
            self.recommendations.append(message)
    
    def clear_recommendations(self) -> None:
        """
        Tüm önerileri temizler.
        
        Examples:
            >>> summary.clear_recommendations()
            >>> len(summary.recommendations)
            0
        """
        self.recommendations.clear()
    
    def has_critical_issues(self) -> bool:
        """
        Kritik güvenlik sorunu olup olmadığını kontrol eder.
        
        Kritik sorunlar:
            - 10'dan fazla güvenlik güncellemesi
            - Güvenlik duvarı kapalı veya kurulu değil
            - Sudo yapılandırması güvensiz
            - 1000'den fazla başarısız giriş denemesi
        
        Returns:
            bool: Kritik sorun varsa True
        
        Examples:
            >>> summary = SecuritySummary(security_updates_count=20, ...)
            >>> assert summary.has_critical_issues() is True
            >>> 
            >>> summary2 = SecuritySummary(security_updates_count=2, firewall_status="Aktif", ...)
            >>> assert summary2.has_critical_issues() is False
        """
        return (
            self.security_updates_count > 10 or
            "Devre Dışı" in self.firewall_status or
            "Kurulu Değil" in self.firewall_status or
            (self.sudo_config_secure is False) or
            (self.failed_login_attempts is not None and self.failed_login_attempts > 1000)
        )
    
    def get_security_score(self) -> int:
        """
        Genel güvenlik skorunu hesaplar (0-100).
        
        Skorlama sistemi çeşitli güvenlik kriterlerine göre puan hesaplar.
        Her kriter belirli bir ağırlığa sahiptir.
        
        Returns:
            int: Güvenlik skoru (100 = mükemmel, 0 = çok kötü)
        
        Examples:
            >>> summary = SecuritySummary(
            ...     security_updates_count=0,
            ...     firewall_status="Aktif",
            ...     apparmor_status="Aktif",
            ...     selinux_status="Kurulu Değil",
            ...     unattended_upgrades="Aktif",
            ...     last_update_check="Bugün",
            ...     sudo_config_secure=True
            ... )
            >>> score = summary.get_security_score()
            >>> assert score >= 90  # Mükemmel yapılandırma
            >>> 
            >>> if score < 50:
            ...     print("🔴 Güvenlik durumu zayıf!")
        
        Note:
            Skorlama kriterleri:
                1. Güvenlik güncellemeleri: -2 puan/güncelleme (max -40)
                2. Güvenlik duvarı kapalı: -30 puan
                3. Otomatik güncelleme kapalı: -15 puan
                4. Sudo güvensiz: -20 puan
                5. MAC sistemi yok: -10 puan
                6. Çok fazla açık port: -10 veya -15 puan
                7. Başarısız giriş saldırısı: -10 veya -15 puan
                8. Son güncelleme zamanı: -10, -15 veya -20 puan
        """
        score = 100
        
        # 1. Güvenlik güncellemeleri (-2 puan/güncelleme, max -40)
        if self.security_updates_count > 0:
            penalty = min(self.security_updates_count * 2, 40)
            score -= penalty
        
        # 2. Güvenlik duvarı (-30 veya -20 puan)
        if "Devre Dışı" in self.firewall_status or "Kurulu Değil" in self.firewall_status:
            score -= 30
        elif "Yapılandırılmamış" in self.firewall_status:
            score -= 20
        
        # 3. Otomatik güncellemeler (-15 veya -10 puan)
        if self.unattended_upgrades == "Yapılandırılmamış":
            score -= 15
        elif self.unattended_upgrades == "Pasif":
            score -= 10
        
        # 4. Sudo yapılandırması (-20 veya -5 puan)
        if self.sudo_config_secure is False:
            score -= 20
        elif self.sudo_config_secure is None:
            score -= 5  # Kontrol edilemedi, küçük ceza
        
        # 5. MAC (Mandatory Access Control) sistemi (-10 puan)
        has_mac = False
        if "Aktif" in self.apparmor_status or "Aktif" in self.selinux_status:
            has_mac = True
        
        if not has_mac:
            if "Kurulu Değil" in self.apparmor_status and "Kurulu Değil" in self.selinux_status:
                score -= 10
        
        # 6. Açık port sayısı (-10 veya -15 puan)
        if self.open_ports_count is not None:
            if self.open_ports_count > 50:
                score -= 15
            elif self.open_ports_count > 20:
                score -= 10
        
        # 7. Başarısız giriş denemeleri (-10 veya -15 puan)
        if self.failed_login_attempts is not None:
            if self.failed_login_attempts > 1000:
                score -= 15  # Ciddi saldırı
            elif self.failed_login_attempts > 100:
                score -= 10
        
        # 8. Son güncelleme zamanı (-10, -15 veya -20 puan)
        if "gün önce" in self.last_update_check:
            try:
                # "30 gün önce" formatından sayıyı çıkar
                days_str = self.last_update_check.split()[0]
                days = int(days_str)
                
                if days > 90:
                    score -= 20
                elif days > 60:
                    score -= 15
                elif days > 30:
                    score -= 10
            except (ValueError, IndexError):
                pass
        
        # Skoru 0-100 aralığında tut
        return max(0, min(100, score))
    
    def get_security_level(self) -> SecurityLevel:
        """
        Güvenlik seviyesini kategorik olarak döndürür.
        
        Güvenlik skoru 0-100 aralığını 5 kategoriye böler.
        
        Returns:
            SecurityLevel: Güvenlik seviyesi kategorisi
        
        Examples:
            >>> summary = SecuritySummary(...)
            >>> level = summary.get_security_level()
            >>> if level == SecurityLevel.CRITICAL:
            ...     print("🔴 ACİL MÜDAHALE GEREKLİ!")
            >>> elif level == SecurityLevel.EXCELLENT:
            ...     print("✅ Güvenlik durumu mükemmel!")
        """
        score = self.get_security_score()
        return SecurityLevel.from_score(score)
    
    def get_status_emoji(self) -> str:
        """
        Güvenlik durumunu emoji olarak döndürür.
        
        Güvenlik skoruna göre görsel bir gösterge sağlar.
        
        Returns:
            str: Durum emojisi (✅, 🟢, ⚠️, 🟠, 🔴)
        
        Examples:
            >>> summary = SecuritySummary(...)
            >>> emoji = summary.get_status_emoji()
            >>> print(f"{emoji} Güvenlik Durumu")
            ✅ Güvenlik Durumu  # veya ⚠️ veya 🔴
        """
        level = self.get_security_level()
        return level.get_emoji()
    
    def get_grade(self) -> str:
        """
        Güvenlik notunu harf olarak döndürür (A-F).
        
        Returns:
            str: Harf notu (A+, A, A-, B+, B, B-, C+, C, C-, D+, D, D-, F)
        
        Examples:
            >>> summary = SecuritySummary(...)
            >>> print(f"Güvenlik Notu: {summary.get_grade()}")
            Güvenlik Notu: B+
        """
        score = self.get_security_score()
        
        if score >= 97:
            return "A+"
        elif score >= 93:
            return "A"
        elif score >= 90:
            return "A-"
        elif score >= 87:
            return "B+"
        elif score >= 83:
            return "B"
        elif score >= 80:
            return "B-"
        elif score >= 77:
            return "C+"
        elif score >= 73:
            return "C"
        elif score >= 70:
            return "C-"
        elif score >= 67:
            return "D+"
        elif score >= 63:
            return "D"
        elif score >= 60:
            return "D-"
        else:
            return "F"
    
    def get_summary_text(self) -> str:
        """
        Güvenlik durumunun kısa özet metnini döndürür.
        
        Returns:
            str: Kullanıcı dostu özet metni
        
        Examples:
            >>> summary = SecuritySummary(...)
            >>> print(summary.get_summary_text())
            🟢 Good - Güvenlik skoru: 85/100 (B). 
            5 güvenlik güncellemesi bekliyor. Güvenlik duvarı aktif.
        """
        emoji = self.get_status_emoji()
        score = self.get_security_score()
        grade = self.get_grade()
        level = self.get_security_level().value
        
        # Ana mesaj
        text = f"{emoji} {level.title()} - Güvenlik skoru: {score}/100 ({grade}). "
        
        # Öne çıkan bilgiler
        highlights = []
        
        if self.security_updates_count > 0:
            highlights.append(f"{self.security_updates_count} güvenlik güncellemesi bekliyor")
        
        if "Aktif" in self.firewall_status:
            highlights.append("Güvenlik duvarı aktif")
        elif "Devre Dışı" in self.firewall_status:
            highlights.append("⚠️  Güvenlik duvarı kapalı")
        
        if self.failed_login_attempts and self.failed_login_attempts > 100:
            highlights.append(f"⚠️  {self.failed_login_attempts} başarısız giriş denemesi")
        
        if highlights:
            text += ". ".join(highlights) + "."
        
        return text
    
    def get_recommendation_count_by_severity(self) -> Dict[str, int]:
        """
        Önerileri şiddete göre sayar.
        
        Returns:
            Dict[str, int]: Şiddet seviyelerine göre öneri sayısı
                {
                    'critical': int,  # 🔴
                    'warning': int,   # ⚠️
                    'info': int,      # 💡 veya ℹ️
                    'success': int    # ✅
                }
        
        Examples:
            >>> summary = SecuritySummary(...)
            >>> counts = summary.get_recommendation_count_by_severity()
            >>> print(f"Kritik: {counts['critical']}, Uyarı: {counts['warning']}")
            Kritik: 2, Uyarı: 3
        """
        counts = {
            'critical': 0,  # 🔴
            'warning': 0,   # ⚠️
            'info': 0,      # 💡 veya ℹ️
            'success': 0    # ✅
        }
        
        for rec in self.recommendations:
            if '🔴' in rec or 'CRİTİK' in rec or 'CRITICAL' in rec:
                counts['critical'] += 1
            elif '⚠️' in rec or 'UYARI' in rec or 'WARNING' in rec:
                counts['warning'] += 1
            elif '✅' in rec or 'BAŞARILI' in rec or 'SUCCESS' in rec:
                counts['success'] += 1
            else:
                counts['info'] += 1
        
        return counts
    
    def needs_immediate_action(self) -> bool:
        """
        Acil eylem gerekip gerekmediğini kontrol eder.
        
        Returns:
            bool: Acil eylem gerekiyorsa True
        
        Examples:
            >>> summary = SecuritySummary(...)
            >>> if summary.needs_immediate_action():
            ...     print("⚠️  ACİL EYLEM GEREKLİ!")
            ...     # Alarm gönder, admin'i bilgilendir
        """
        return (
            self.get_security_score() < 50 or
            self.has_critical_issues() or
            self.security_updates_count > 20 or
            (self.failed_login_attempts is not None and self.failed_login_attempts > 2000)
        )


# =============================================================================
# PORT INFO (Ağ Port Bilgileri)
# =============================================================================

@dataclass
class PortInfo:
    """
    Ağ port bilgilerini tutan veri sınıfı.
    
    Sistemde dinlemede olan (LISTEN) portlar hakkında detaylı bilgi içerir.
    Port numarası, protokol, bağlı process ve güvenlik durumu gibi bilgileri tutar.
    
    Attributes:
        protocol (str): Protokol tipi (tcp, udp, tcp6, udp6)
        address (str): Dinlenen adres
            - "0.0.0.0": Tüm IPv4 adresleri (public)
            - "127.0.0.1": Localhost (local)
            - "::": Tüm IPv6 adresleri (public)
            - "::1": IPv6 localhost
        port (str): Port numarası (string formatında)
        process (str): Port'u kullanan process adı
        pid (Optional[int]): Process ID
        user (Optional[str]): Process sahibi kullanıcı
        is_privileged (bool): Ayrıcalıklı port mu (< 1024)
            - Otomatik hesaplanır (__post_init__ içinde)
    
    Examples:
        >>> # Temel oluşturma
        >>> port = PortInfo(
        ...     protocol="tcp",
        ...     address="0.0.0.0",
        ...     port="80",
        ...     process="nginx"
        ... )
        >>> 
        >>> # Privileged port kontrolü (otomatik)
        >>> print(port.is_privileged)
        True
        >>> 
        >>> # Display name
        >>> print(port.get_display_name())
        'tcp:0.0.0.0:80 (nginx)'
        >>> 
        >>> # Public port kontrolü
        >>> if port.is_public():
        ...     print("⚠️  Bu port internete açık!")
        >>> 
        >>> # Risk seviyesi
        >>> risk = port.get_security_risk()
        >>> print(f"Risk: {risk}")  # LOW, MEDIUM, HIGH
    
    Note:
        - is_privileged field'ı __post_init__ içinde otomatik hesaplanır
        - Port numarası < 1024 ise True olur
        - Privileged portlar sadece root tarafından açılabilir
    
    See Also:
        - get_listening_ports(): Bu dataclass'ı oluşturan fonksiyon
    """
    
    protocol: str
    address: str
    port: str
    process: str
    pid: Optional[int] = None
    user: Optional[str] = None
    is_privileged: bool = False  # __post_init__'de hesaplanır
    
    def __post_init__(self):
        """
        Port numarasına göre is_privileged field'ını hesaplar.
        
        Privileged portlar (< 1024) sadece root tarafından açılabilir.
        Bu, güvenlik analizi için önemli bir göstergedir.
        """
        try:
            port_num = int(self.port)
            self.is_privileged = port_num < 1024
        except (ValueError, TypeError):
            # Port numarası parse edilemezse (örn: "ssh")
            # varsayılan değer False kalır
            log.debug(f"Port numarası parse edilemedi: {self.port}")
            pass
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Dataclass'ı dictionary'e çevirir.
        
        Returns:
            Dict[str, Any]: Tüm field'ları içeren dictionary
        """
        return asdict(self)
    
    def is_public(self) -> bool:
        """
        Port'un internete açık olup olmadığını kontrol eder.
        
        Returns:
            bool: Port public ise True
        
        Examples:
            >>> port = PortInfo(address="0.0.0.0", ...)
            >>> assert port.is_public() is True
            >>> 
            >>> port = PortInfo(address="127.0.0.1", ...)
            >>> assert port.is_public() is False
        """
        public_addresses = ["0.0.0.0", "::", "[::]"]
        return self.address in public_addresses
    
    def is_localhost(self) -> bool:
        """
        Port'un sadece localhost'a bağlı olup olmadığını kontrol eder.
        
        Returns:
            bool: Localhost ise True
        
        Examples:
            >>> port = PortInfo(address="127.0.0.1", ...)
            >>> assert port.is_localhost() is True
        """
        localhost_addresses = ["127.0.0.1", "::1", "[::1]", "localhost"]
        return self.address in localhost_addresses
    
    def get_display_name(self) -> str:
        """
        Port bilgisinin okunabilir string temsilini döndürür.
        
        Returns:
            str: Formatlanmış port bilgisi
        
        Examples:
            >>> port = PortInfo(protocol="tcp", address="0.0.0.0", port="80", process="nginx")
            >>> print(port.get_display_name())
            'tcp:0.0.0.0:80 (nginx)'
            >>> 
            >>> port_with_pid = PortInfo(..., pid=1234)
            >>> print(port_with_pid.get_display_name())
            'tcp:0.0.0.0:80 (nginx) [PID:1234]'
        """
        base = f"{self.protocol}:{self.address}:{self.port}"
        if self.process:
            base += f" ({self.process})"
        if self.pid:
            base += f" [PID:{self.pid}]"
        return base
    
    def get_security_risk(self) -> str:
        """
        Port'un güvenlik risk seviyesini değerlendirir.
        
        Returns:
            str: Risk seviyesi (LOW, MEDIUM, HIGH)
        
        Risk Kriterleri:
            HIGH:   Public + Privileged (80, 443, 22 hariç)
            MEDIUM: Public + SSH (22) VEYA Public + Unprivileged
            LOW:    Localhost VEYA Güvenli servisler (80, 443)
        
        Examples:
            >>> port = PortInfo(address="0.0.0.0", port="22", ...)
            >>> print(port.get_security_risk())
            'MEDIUM'  # Public SSH
            >>> 
            >>> port = PortInfo(address="0.0.0.0", port="8080", ...)
            >>> print(port.get_security_risk())
            'MEDIUM'  # Public unprivileged
            >>> 
            >>> port = PortInfo(address="127.0.0.1", port="3306", ...)
            >>> print(port.get_security_risk())
            'LOW'  # Localhost MySQL
        """
        # Public ve privileged portlar yüksek risk
        if self.is_public() and self.is_privileged:
            # Ama bazı servisler beklenir
            safe_privileged = ["80", "443", "22"]
            if self.port not in safe_privileged:
                return "HIGH"
            elif self.port == "22":
                return "MEDIUM"
            else:
                return "LOW"
        
        # Public ama unprivileged
        elif self.is_public():
            return "MEDIUM"
        
        # Localhost
        else:
            return "LOW"


# =============================================================================
# SSH AUDIT (SSH Yapılandırma Denetimi)
# =============================================================================

@dataclass
class SSHAudit:
    """
    SSH yapılandırma denetim sonuçlarını tutan veri sınıfı.
    
    SSH sunucusunun güvenlik yapılandırmasını analiz eder ve risk seviyesi
    hesaplar. Root girişi, şifre doğrulama, boş şifre izni gibi kritik
    güvenlik ayarlarını kontrol eder.
    
    Attributes:
        config_exists (bool): SSH config dosyası mevcut mu
        port (str): SSH port numarası
        root_login_permitted (Optional[bool]): Root girişi izni
        password_auth_enabled (Optional[bool]): Şifre ile giriş izni
        empty_passwords_permitted (Optional[bool]): Boş şifre izni (KRİTİK!)
        ssh_protocol (Optional[str]): SSH protokol versiyonu (1 veya 2)
        permit_user_environment (Optional[bool]): Kullanıcı environment izni
        x11_forwarding (Optional[bool]): X11 forwarding izni
        max_auth_tries (Optional[int]): Maksimum giriş denemesi sayısı
        recommendations (List[str]): Güvenlik önerileri listesi
        risk_level (str): Genel risk seviyesi
            - "CRITICAL": Boş şifre izni var
            - "HIGH": Root + şifre girişi aktif
            - "MEDIUM": Root veya varsayılan port + şifre
            - "LOW": Güvenli yapılandırma
    
    Examples:
        >>> # Temel oluşturma
        >>> audit = SSHAudit(
        ...     config_exists=True,
        ...     port="22",
        ...     root_login_permitted=True,
        ...     password_auth_enabled=True,
        ...     empty_passwords_permitted=False,
        ...     ssh_protocol="2"
        ... )
        >>> 
        >>> # Risk seviyesi (otomatik hesaplanır)
        >>> print(audit.risk_level)
        'HIGH'
        >>> 
        >>> # Öneri ekleme
        >>> audit.add_recommendation("Root girişini kapatın")
        >>> 
        >>> # Güvenli mi?
        >>> if not audit.is_secure():
        ...     print("⚠️  SSH yapılandırması güvenli değil!")
        >>> 
        >>> # Risk emojisi
        >>> print(f"{audit.get_risk_emoji()} SSH Risk: {audit.risk_level}")
        🔴 SSH Risk: HIGH
        >>> 
        >>> # Güvenlik skoru
        >>> score = audit.get_security_score()
        >>> print(f"SSH Skoru: {score}/100")
        SSH Skoru: 60/100
    
    Note:
        - risk_level field'ı __post_init__ içinde otomatik hesaplanır
        - Güvenlik ayarlarına göre dinamik olarak belirlenir
        - _calculate_risk_level() metodu risk algoritmasını uygular
    
    See Also:
        - audit_ssh_config(): Bu dataclass'ı oluşturan fonksiyon
        - SSHSecurityLevel: SSH risk seviyesi enum'u
    """
    
    # Required fields
    config_exists: bool
    port: str
    
    # Security settings (Optional)
    root_login_permitted: Optional[bool] = None
    password_auth_enabled: Optional[bool] = None
    empty_passwords_permitted: Optional[bool] = None
    ssh_protocol: Optional[str] = None
    permit_user_environment: Optional[bool] = None
    x11_forwarding: Optional[bool] = None
    max_auth_tries: Optional[int] = None
    
    # Calculated fields
    recommendations: List[str] = field(default_factory=list)
    risk_level: str = "LOW"  # __post_init__'de hesaplanır
    
    def __post_init__(self):
        """
        Risk seviyesini otomatik hesaplar.
        
        Güvenlik ayarlarına göre risk seviyesini belirler:
            - CRITICAL: Boş şifre izni var
            - HIGH: Root + şifre girişi aktif
            - MEDIUM: Root veya varsayılan port + şifre
            - LOW: Güvenli yapılandırma
        """
        self._calculate_risk_level()
    
    def _calculate_risk_level(self) -> None:
        """
        Güvenlik ayarlarına göre risk seviyesini hesaplar.
        
        Öncelik sırası (en kritikten en az kritike):
            1. Boş şifre izni (CRITICAL)
            2. Root + şifre girişi (HIGH)
            3. Root veya (şifre + port 22) (MEDIUM)
            4. Diğer durumlar (LOW)
        """
        # CRITICAL: Boş şifre izni
        if self.empty_passwords_permitted:
            self.risk_level = "CRITICAL"
            return
        
        # HIGH: Root ve şifre girişi ikisi de aktif
        if self.root_login_permitted and self.password_auth_enabled:
            self.risk_level = "HIGH"
            return
        
        # MEDIUM: Root aktif VEYA (şifre + varsayılan port)
        if self.root_login_permitted:
            self.risk_level = "MEDIUM"
            return
        
        if self.password_auth_enabled and self.port == "22":
            self.risk_level = "MEDIUM"
            return
        
        # LOW: Güvenli
        self.risk_level = "LOW"
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Dataclass'ı dictionary'e çevirir.
        
        Returns:
            Dict[str, Any]: Tüm field'ları içeren dictionary
        """
        return asdict(self)
    
    def add_recommendation(self, message: str) -> None:
        """
        Güvenlik önerisi ekler.
        
        Args:
            message: Eklenecek öneri mesajı
        
        Examples:
            >>> audit.add_recommendation("🔴 Root girişini kapatın")
        """
        if message and message not in self.recommendations:
            self.recommendations.append(message)
    
    def is_secure(self) -> bool:
        """
        SSH yapılandırmasının güvenli olup olmadığını kontrol eder.
        
        Returns:
            bool: Risk seviyesi LOW ise True
        
        Examples:
            >>> audit = SSHAudit(...)
            >>> if not audit.is_secure():
            ...     print("⚠️  SSH yapılandırması güvenli değil!")
        """
        return self.risk_level == "LOW"
    
    def get_risk_emoji(self) -> str:
        """
        Risk seviyesini emoji olarak döndürür.
        
        Returns:
            str: Risk emojisi (🔴, ⚠️, ✅)
        
        Examples:
            >>> audit.get_risk_emoji()
            '🔴'  # veya '⚠️' veya '✅'
        """
        risk_emojis = {
            "CRITICAL": "🔴",
            "HIGH": "🔴",
            "MEDIUM": "⚠️",
            "LOW": "✅"
        }
        return risk_emojis.get(self.risk_level, "❓")
    
    def get_security_score(self) -> int:
        """
        SSH güvenlik skorunu hesaplar (0-100).
        
        Returns:
            int: Güvenlik skoru
        
        Examples:
            >>> audit = SSHAudit(...)
            >>> score = audit.get_security_score()
            >>> print(f"SSH Güvenlik Skoru: {score}/100")
            SSH Güvenlik Skoru: 60/100
        
        Note:
            Skorlama kriterleri:
                - empty_passwords_permitted: -60 puan (KRİTİK)
                - root_login_permitted: -25 puan
                - password_auth_enabled: -15 puan
                - port == "22": -10 puan
                - ssh_protocol == "1": -40 puan (eski protokol)
                - x11_forwarding: -5 puan
                - permit_user_environment: -10 puan
                - max_auth_tries > 3: -5 puan
        """
        score = 100
        
        if self.empty_passwords_permitted:
            score -= 60  # Kritik
        if self.root_login_permitted:
            score -= 25
        if self.password_auth_enabled:
            score -= 15
        if self.port == "22":
            score -= 10
        if self.ssh_protocol == "1":
            score -= 40  # Eski protokol
        if self.x11_forwarding:
            score -= 5
        if self.permit_user_environment:
            score -= 10
        if self.max_auth_tries and self.max_auth_tries > 3:
            score -= 5
        
        return max(0, score)


# =============================================================================
# MODULE METADATA
# =============================================================================

__all__ = [
    'SecuritySummary',
    'PortInfo',
    'SSHAudit',
]