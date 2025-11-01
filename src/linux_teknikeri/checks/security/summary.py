"""
Sistem Güvenlik Özeti Modülü
=============================

Sistem güvenliği hakkında kapsamlı özet bilgileri toplayan modül.

Fonksiyonlar:
    get_security_summary()              - Ana fonksiyon (tüm kontrolleri toplar)
    _check_security_updates()           - Güvenlik güncellemelerini kontrol eder
    _check_firewall_status()            - Güvenlik duvarı durumunu kontrol eder
    _check_apparmor_status()            - AppArmor durumunu kontrol eder
    _check_selinux_status()             - SELinux durumunu kontrol eder
    _check_unattended_upgrades()        - Otomatik güncellemeleri kontrol eder
    _get_last_update_time()             - Son güncelleme zamanını bulur
    _parse_apt_date()                   - APT tarih formatını parse eder
    _check_sudo_config()                - Sudo yapılandırmasını kontrol eder
    _check_sudo_config_comprehensive()  - Kapsamlı sudo analizi (bonus)
    _generate_security_recommendations()- Güvenlik önerileri üretir

Kontrol Edilen:
    - Bekleyen güvenlik güncellemeleri
    - Güvenlik duvarı (UFW/firewalld/iptables)
    - SELinux/AppArmor durumu
    - Otomatik güncelleme yapılandırması
    - Son güncelleme zamanı
    - Sudo yapılandırması güvenliği

Author: ozturu68
Version: 0.5.0
Date: 2025-11-01
License: MIT
"""

import os
import re
import logging
from typing import Dict, List, Optional, Any
from pathlib import Path
from datetime import datetime

# Local imports
from .models import SecuritySummary
from ...utils.command_runner import (
    run_command,
    is_command_available,
    safe_command_output
)

# Logger
log = logging.getLogger(__name__)


# =============================================================================
# ANA FONKSİYON
# =============================================================================

def get_security_summary() -> Dict[str, Any]:
    """
    Sistem güvenliği hakkında genel özet bilgiler toplar.
    
    Tüm güvenlik kontrollerini sırayla çalıştırıp bir SecuritySummary
    dataclass'ı oluşturur ve dictionary formatında döndürür.
    
    Kontrol Edilen:
        1. Bekleyen güvenlik güncellemeleri
        2. Güvenlik duvarı (UFW/firewalld/iptables) durumu
        3. SELinux/AppArmor durumu
        4. Otomatik güncelleme yapılandırması
        5. Son güncelleme zamanı
        6. Sudo yapılandırması güvenliği
        7. Güvenlik önerileri (otomatik oluşturulur)
    
    Returns:
        Dict[str, Any]: Güvenlik özeti bilgileri
            {
                'security_updates_count': int,
                'firewall_status': str,
                'apparmor_status': str,
                'selinux_status': str,
                'unattended_upgrades': str,
                'last_update_check': str,
                'sudo_config_secure': Optional[bool],
                'open_ports_count': Optional[int],
                'failed_login_attempts': Optional[int],
                'recommendations': List[str],
                # Plus helper method results:
                'get_security_score': Callable[[], int],
                'get_security_level': Callable[[], SecurityLevel],
                'has_critical_issues': Callable[[], bool],
                ...
            }
    
    Examples:
        >>> from linux_teknikeri.checks.security import get_security_summary
        >>> 
        >>> # Temel kullanım
        >>> summary = get_security_summary()
        >>> print(f"Güvenlik güncellemesi: {summary['security_updates_count']}")
        Güvenlik güncellemesi: 5
        >>> 
        >>> # Skor hesaplama
        >>> summary_obj = SecuritySummary(**summary)
        >>> score = summary_obj.get_security_score()
        >>> print(f"Güvenlik Skoru: {score}/100")
        Güvenlik Skoru: 85/100
        >>> 
        >>> # Kritik sorun kontrolü
        >>> if summary['security_updates_count'] > 10:
        ...     print("⚠️  Çok fazla güvenlik güncellemesi bekliyor!")
        >>> 
        >>> if "Devre Dışı" in summary['firewall_status']:
        ...     print("🔥 Güvenlik duvarı kapalı!")
    
    Performance:
        Ortalama süre: 2-5 saniye
        - apt-check: ~1-2 saniye
        - Firewall check: ~0.5 saniye
        - AppArmor/SELinux: ~0.5 saniye
        - Sudo config: ~0.5 saniye
        - Diğerleri: ~0.5 saniye
    
    Note:
        - Bazı kontroller sudo yetkisi gerektirir
        - Hata durumunda "Bilinmiyor" veya -1 değerleri döner
        - Exception raise etmez, hataları log'lar
    
    See Also:
        - SecuritySummary: Döndürülen veri modeli
        - get_listening_ports(): Açık portları listeler
        - audit_ssh_config(): SSH yapılandırmasını kontrol eder
    """
    log.info("Güvenlik özeti toplanıyor...")
    
    # SecuritySummary dataclass oluştur (başlangıç değerleri)
    summary = SecuritySummary(
        security_updates_count=-1,
        firewall_status='Bilinmiyor',
        apparmor_status='Bilinmiyor',
        selinux_status='Bilinmiyor',
        unattended_upgrades='Bilinmiyor',
        last_update_check='Bilinmiyor'
    )
    
    # 1. Güvenlik güncellemeleri kontrolü
    try:
        summary.security_updates_count = _check_security_updates()
        log.debug(f"Güvenlik güncellemesi: {summary.security_updates_count}")
    except Exception as e:
        log.error(f"Güvenlik güncellemesi kontrolü başarısız: {e}", exc_info=True)
        summary.security_updates_count = -1
    
    # 2. Güvenlik duvarı durumu
    try:
        summary.firewall_status = _check_firewall_status()
        log.debug(f"Güvenlik duvarı: {summary.firewall_status}")
    except Exception as e:
        log.error(f"Güvenlik duvarı kontrolü başarısız: {e}", exc_info=True)
        summary.firewall_status = "Kontrol Edilemedi"
    
    # 3. AppArmor durumu
    try:
        summary.apparmor_status = _check_apparmor_status()
        log.debug(f"AppArmor: {summary.apparmor_status}")
    except Exception as e:
        log.error(f"AppArmor kontrolü başarısız: {e}", exc_info=True)
        summary.apparmor_status = "Kontrol Edilemedi"
    
    # 4. SELinux durumu
    try:
        summary.selinux_status = _check_selinux_status()
        log.debug(f"SELinux: {summary.selinux_status}")
    except Exception as e:
        log.error(f"SELinux kontrolü başarısız: {e}", exc_info=True)
        summary.selinux_status = "Kontrol Edilemedi"
    
    # 5. Otomatik güncellemeler
    try:
        summary.unattended_upgrades = _check_unattended_upgrades()
        log.debug(f"Otomatik güncellemeler: {summary.unattended_upgrades}")
    except Exception as e:
        log.error(f"Otomatik güncelleme kontrolü başarısız: {e}", exc_info=True)
        summary.unattended_upgrades = "Kontrol Edilemedi"
    
    # 6. Son güncelleme zamanı
    try:
        summary.last_update_check = _get_last_update_time()
        log.debug(f"Son güncelleme: {summary.last_update_check}")
    except Exception as e:
        log.error(f"Son güncelleme zamanı alınamadı: {e}", exc_info=True)
        summary.last_update_check = "Kontrol Edilemedi"
    
    # 7. Sudo yapılandırması güvenliği
    try:
        summary.sudo_config_secure = _check_sudo_config()
        log.debug(f"Sudo güvenliği: {summary.sudo_config_secure}")
    except Exception as e:
        log.error(f"Sudo config kontrolü başarısız: {e}", exc_info=True)
        summary.sudo_config_secure = None
    
    # 8. Güvenlik önerileri üret
    try:
        summary.recommendations = _generate_security_recommendations(summary)
        log.debug(f"Öneriler: {len(summary.recommendations)} adet")
    except Exception as e:
        log.error(f"Öneri oluşturma başarısız: {e}", exc_info=True)
        summary.recommendations = ["⚠️  Güvenlik önerileri oluşturulamadı"]
    
    log.info(f"Güvenlik özeti hazır (skor: {summary.get_security_score()}/100)")
    
    return summary.to_dict()


# =============================================================================
# HELPER FUNCTIONS - GÜVENLİK GÜNCELLEMELERİ
# =============================================================================

def _check_security_updates() -> int:
    """
    Bekleyen güvenlik güncellemelerini sayar.
    
    Üç farklı yöntem dener (öncelik sırasıyla):
        1. apt-check komutu (Ubuntu/Debian)
        2. apt list --upgradable (security keyword ile)
        3. apt-get -s upgrade (simulation)
    
    Returns:
        int: Güvenlik güncellemesi sayısı (-1 = tespit edilemedi)
    
    Examples:
        >>> count = _check_security_updates()
        >>> if count > 0:
        ...     print(f"⚠️  {count} güvenlik güncellemesi bekliyor")
    
    Note:
        - apt-check çıktısı stderr'e yazılır (bug değil, özellik!)
        - Format: "paketsayısı;güvenliksayısı"
    """
    # Yöntem 1: apt-check (Ubuntu/Debian)
    if os.path.exists("/usr/lib/update-notifier/apt-check"):
        try:
            stdout, stderr, retcode = run_command(
                ["/usr/lib/update-notifier/apt-check"],
                timeout=15,
                suppress_stderr=False  # apt-check stderr'e yazar!
            )
            
            # apt-check çıktıyı stderr'e yazar (bug değil, özellik!)
            output = stderr if stderr else stdout
            
            if retcode == 0 and output:
                # Çıktı formatı: "paketsayısı;güvenliksayısı"
                parts = output.strip().split(';')
                if len(parts) >= 2:
                    security_count = int(parts[1])
                    log.debug(f"apt-check: {security_count} güvenlik güncellemesi")
                    return security_count
        except (ValueError, IndexError) as e:
            log.warning(f"apt-check çıktısı parse edilemedi: {e}")
        except Exception as e:
            log.warning(f"apt-check çalıştırılamadı: {e}")
    
    # Yöntem 2: apt list --upgradable
    if is_command_available("apt"):
        try:
            stdout, stderr, retcode = run_command(
                ["apt", "list", "--upgradable"],
                timeout=15,
                suppress_stderr=True
            )
            
            if retcode == 0:
                # "security" kelimesini içeren satırları say
                security_lines = [
                    line for line in stdout.split('\n')
                    if 'security' in line.lower()
                ]
                count = len(security_lines)
                log.debug(f"apt list: {count} güvenlik güncellemesi")
                return count
        except Exception as e:
            log.warning(f"apt list çalıştırılamadı: {e}")
    
    # Yöntem 3: apt-get -s upgrade (simulation)
    if is_command_available("apt-get"):
        try:
            stdout, stderr, retcode = run_command(
                ["apt-get", "-s", "upgrade"],
                timeout=15,
                suppress_stderr=True
            )
            
            if retcode == 0:
                # "security" içeren paketleri say
                security_count = stdout.lower().count('security')
                log.debug(f"apt-get -s: {security_count} güvenlik güncellemesi")
                return security_count
        except Exception as e:
            log.warning(f"apt-get -s çalıştırılamadı: {e}")
    
    log.warning("Güvenlik güncellemeleri kontrol edilemedi (hiçbir yöntem çalışmadı)")
    return -1


# =============================================================================
# HELPER FUNCTIONS - GÜVENLİK DUVARI
# =============================================================================

def _check_firewall_status() -> str:
    """
    Güvenlik duvarı durumunu kontrol eder (UFW, firewalld, iptables).
    
    Üç firewall sistemini sırayla kontrol eder:
        1. UFW (Ubuntu/Debian)
        2. firewalld (RHEL/CentOS/Fedora)
        3. iptables (Genel Linux)
    
    Returns:
        str: Güvenlik duvarı durumu
            - "Aktif (UFW, 10 kural)"
            - "Devre Dışı (UFW)"
            - "Aktif (firewalld)"
            - "Aktif (iptables)"
            - "Yapılandırılmamış (iptables)"
            - "Kurulu Değil"
            - "Yetki Gerekli"
    
    Examples:
        >>> status = _check_firewall_status()
        >>> if "Devre Dışı" in status or "Kurulu Değil" in status:
        ...     print("🔥 Güvenlik duvarı kapalı!")
    """
    # 1. UFW kontrolü (Ubuntu/Debian)
    if is_command_available("ufw"):
        stdout, stderr, retcode = run_command(
            ["sudo", "ufw", "status"],
            timeout=5,
            suppress_stderr=True
        )
        
        # Yetki kontrolü
        if retcode != 0 and ("password" in stderr.lower() or "denied" in stderr.lower()):
            log.warning("UFW kontrolü için yetki gerekli")
            return "Yetki Gerekli"
        
        # Durum kontrolü
        if "inactive" in stdout.lower() or "etkin değil" in stdout.lower():
            log.debug("UFW devre dışı")
            return "Devre Dışı (UFW)"
        elif "active" in stdout.lower() or "etkin" in stdout.lower():
            # Aktif kuralları say
            rule_count = stdout.lower().count('allow') + stdout.lower().count('deny')
            log.debug(f"UFW aktif ({rule_count} kural)")
            return f"Aktif (UFW, {rule_count} kural)"
    
    # 2. firewalld kontrolü (RHEL/CentOS/Fedora)
    if is_command_available("firewall-cmd"):
        stdout, stderr, retcode = run_command(
            ["sudo", "firewall-cmd", "--state"],
            timeout=5,
            suppress_stderr=True
        )
        
        if retcode == 0 and "running" in stdout.lower():
            log.debug("firewalld aktif")
            return "Aktif (firewalld)"
        elif retcode == 0 and "not running" in stdout.lower():
            log.debug("firewalld devre dışı")
            return "Devre Dışı (firewalld)"
    
    # 3. iptables kontrolü (son çare)
    if is_command_available("iptables"):
        stdout, stderr, retcode = run_command(
            ["sudo", "iptables", "-L", "-n"],
            timeout=5,
            suppress_stderr=True
        )
        
        if retcode == 0:
            # Eğer policy DROP veya REJECT varsa aktif
            if "DROP" in stdout or "REJECT" in stdout:
                log.debug("iptables aktif (DROP/REJECT kuralları var)")
                return "Aktif (iptables)"
            else:
                log.debug("iptables yapılandırılmamış")
                return "Yapılandırılmamış (iptables)"
    
    log.warning("Güvenlik duvarı bulunamadı")
    return "Kurulu Değil"


# =============================================================================
# HELPER FUNCTIONS - MAC (MANDATORY ACCESS CONTROL)
# =============================================================================

def _check_apparmor_status() -> str:
    """
    AppArmor durumunu kontrol eder (Debian/Ubuntu).
    
    Returns:
        str: AppArmor durumu
            - "Aktif (25/30 profil enforce modda)"
            - "Yüklü Değil"
            - "Kurulu Değil"
            - "Kontrol Edilemedi"
    
    Examples:
        >>> status = _check_apparmor_status()
        >>> if "Kurulu Değil" in status:
        ...     print("💡 AppArmor kurulumu önerilir")
    """
    if not is_command_available("aa-status"):
        return "Kurulu Değil"
    
    stdout, stderr, retcode = run_command(
        ["sudo", "aa-status"],
        timeout=5,
        suppress_stderr=True
    )
    
    if retcode != 0:
        log.warning(f"AppArmor kontrolü başarısız: {stderr}")
        return "Kontrol Edilemedi"
    
    # Module yüklü mü?
    if "apparmor module is loaded" in stdout.lower():
        # Kaç profil yüklü?
        profiles_match = re.search(r'(\d+) profiles are loaded', stdout)
        enforce_match = re.search(r'(\d+) profiles are in enforce mode', stdout)
        
        if profiles_match and enforce_match:
            total = profiles_match.group(1)
            enforced = enforce_match.group(1)
            log.debug(f"AppArmor aktif ({enforced}/{total} profil enforce modda)")
            return f"Aktif ({enforced}/{total} profil enforce modda)"
        else:
            return "Aktif"
    
    return "Yüklü Değil"


def _check_selinux_status() -> str:
    """
    SELinux durumunu kontrol eder (RHEL/CentOS/Fedora).
    
    Returns:
        str: SELinux durumu
            - "Aktif (Enforcing)"
            - "Uyarı Modu (Permissive)"
            - "Devre Dışı"
            - "Kurulu Değil (Debian/Ubuntu'da normal)"
    
    Examples:
        >>> status = _check_selinux_status()
        >>> if status == "Aktif (Enforcing)":
        ...     print("✅ SELinux tam koruma modunda")
    """
    if is_command_available("getenforce"):
        status = safe_command_output(["getenforce"], default="Bilinmiyor")
        
        if status == "Enforcing":
            return "Aktif (Enforcing)"
        elif status == "Permissive":
            return "Uyarı Modu (Permissive)"
        elif status == "Disabled":
            return "Devre Dışı"
        
        return status
    
    return "Kurulu Değil (Debian/Ubuntu'da normal)"


# =============================================================================
# HELPER FUNCTIONS - OTOMATİK GÜNCELLEMELER
# =============================================================================

def _check_unattended_upgrades() -> str:
    """
    Otomatik güncelleme yapılandırmasını kontrol eder.
    
    /etc/apt/apt.conf.d/20auto-upgrades dosyasını kontrol eder.
    
    Returns:
        str: Otomatik güncelleme durumu
            - "Aktif (Güvenlik + Paket Listesi)"
            - "Aktif (Sadece Güvenlik)"
            - "Pasif"
            - "Yapılandırılmamış"
            - "Kontrol Edilemedi (Yetki)"
    
    Examples:
        >>> status = _check_unattended_upgrades()
        >>> if status == "Yapılandırılmamış":
        ...     print("💡 Otomatik güncellemeler önerilir")
    """
    config_file = Path("/etc/apt/apt.conf.d/20auto-upgrades")
    
    if not config_file.exists():
        log.debug("Otomatik güncelleme config dosyası yok")
        return "Yapılandırılmamış"
    
    try:
        content = config_file.read_text()
        
        # Unattended-Upgrade aktif mi?
        if 'APT::Periodic::Unattended-Upgrade "1"' in content:
            # Güvenlik güncellemeleri otomatik mi?
            if 'APT::Periodic::Update-Package-Lists "1"' in content:
                log.debug("Otomatik güncellemeler tam aktif")
                return "Aktif (Güvenlik + Paket Listesi)"
            else:
                log.debug("Otomatik güncellemeler kısmi aktif")
                return "Aktif (Sadece Güvenlik)"
        else:
            log.debug("Otomatik güncellemeler pasif")
            return "Pasif"
    
    except PermissionError:
        log.warning("Otomatik güncelleme config okuma yetkisi yok")
        return "Kontrol Edilemedi (Yetki)"
    except Exception as e:
        log.error(f"Otomatik güncelleme kontrolü hatası: {e}", exc_info=True)
        return "Hata"


# =============================================================================
# HELPER FUNCTIONS - SON GÜNCELLEME ZAMANI
# =============================================================================

def _get_last_update_time() -> str:
    """
    Son apt güncelleme zamanını tespit eder.
    
    /var/log/apt/history.log dosyasından son "Start-Date" satırını okur
    ve kullanıcı dostu formata çevirir.
    
    Returns:
        str: Son güncelleme zamanı
            - "Bugün (2025-11-01 10:30:25)"
            - "Dün (2025-10-31 15:20:10)"
            - "5 gün önce (2025-10-27 09:15:30)"
            - "Bilinmiyor"
            - "Güncelleme kaydı yok"
            - "Okunamadı"
    
    Examples:
        >>> time_str = _get_last_update_time()
        >>> if "gün önce" in time_str:
        ...     days = int(time_str.split()[0])
        ...     if days > 30:
        ...         print("⚠️  Uzun süredir güncelleme yapılmamış!")
    
    Note:
        - APT tarih formatı: 'YYYY-MM-DD  HH:MM:SS' (2 boşluk!)
        - tail -n 100 kullanılır (performans için)
        - Sudo yetkisi gerekmez
    """
    apt_history = Path("/var/log/apt/history.log")
    
    # Dosya kontrolü
    if not apt_history.exists():
        log.debug("APT history dosyası bulunamadı")
        return "Bilinmiyor"
    
    if not apt_history.is_file():
        log.warning(f"{apt_history} bir dosya değil")
        return "Bilinmiyor"
    
    try:
        # Son 100 satırı oku (performans için)
        stdout, stderr, retcode = run_command(
            ["tail", "-n", "100", str(apt_history)],
            timeout=5,
            suppress_stderr=True
        )
        
        if retcode != 0:
            log.warning(f"APT history okunamadı: {stderr}")
            return "Okunamadı"
        
        # Son Start-Date satırını bul
        # Format: Start-Date: 2025-11-01  10:30:25
        date_pattern = r'Start-Date:\s*(.+)'
        dates = re.findall(date_pattern, stdout)
        
        if not dates:
            log.debug("APT history'de Start-Date bulunamadı")
            return "Güncelleme kaydı yok"
        
        # Son tarihi al ve parse et
        last_date_str = dates[-1].strip()
        return _parse_apt_date(last_date_str)
    
    except OSError as e:
        log.error(f"APT history dosyası okuma hatası: {e}")
        return "Dosya Okuma Hatası"
    except Exception as e:
        log.error(f"Son güncelleme zamanı alınamadı: {e}", exc_info=True)
        return "Hata"


def _parse_apt_date(date_str: str) -> str:
    """
    APT tarih string'ini parse eder ve kullanıcı dostu formata çevirir.
    
    Args:
        date_str: APT log'undaki tarih string'i
                  Format: "2025-11-01  10:30:25" (2 boşluk!)
    
    Returns:
        str: Formatlanmış tarih açıklaması
            - "Bugün (2025-11-01 10:30:25)"
            - "Dün (2025-10-31 15:20:10)"
            - "7 gün önce (2025-10-25 15:20:10)"
            - Orijinal string (parse edilemezse)
    
    Examples:
        >>> _parse_apt_date("2025-11-01  10:30:25")
        'Bugün (2025-11-01  10:30:25)'
        >>> 
        >>> _parse_apt_date("2025-10-25  15:20:10")
        '7 gün önce (2025-10-25  15:20:10)'
    
    Note:
        APT log formatı 2 boşluk kullanır: '%Y-%m-%d  %H:%M:%S'
        Eğer parse edilemezse, orijinal string döndürülür.
    """
    # APT log formatı - 2 boşluk var!
    apt_date_formats = [
        '%Y-%m-%d  %H:%M:%S',  # Standart: 2 space
        '%Y-%m-%d %H:%M:%S',   # Fallback: 1 space
        '%Y-%m-%d',            # Sadece tarih
    ]
    
    date_obj: Optional[datetime] = None
    
    # Farklı formatları dene
    for date_format in apt_date_formats:
        try:
            date_obj = datetime.strptime(date_str, date_format)
            break
        except ValueError:
            continue
    
    # Parse edilemedi, orijinal string döndür
    if date_obj is None:
        log.warning(f"APT tarihi parse edilemedi: {date_str}")
        return str(date_str)
    
    # Kaç gün önce?
    days_ago = (datetime.now() - date_obj).days
    
    # Kullanıcı dostu açıklama
    if days_ago == 0:
        return f"Bugün ({date_str})"
    elif days_ago == 1:
        return f"Dün ({date_str})"
    elif days_ago < 0:
        # Gelecek tarih (saat farkı?)
        return f"Son güncelleme: {date_str}"
    else:
        return f"{days_ago} gün önce ({date_str})"


# =============================================================================
# HELPER FUNCTIONS - SUDO YAPILANDIRMA
# =============================================================================

def _check_sudo_config() -> Optional[bool]:
    """
    Sudo yapılandırmasının güvenli olup olmadığını kontrol eder.
    
    /etc/sudoers dosyasını analiz ederek tehlikeli yapılandırmaları tespit eder.
    NOPASSWD: ALL gibi kritik güvenlik açıklarını arar.
    
    Returns:
        Optional[bool]:
            - True: Güvenli yapılandırma
            - False: Güvensiz yapılandırma tespit edildi
            - None: Kontrol edilemedi (yetki eksikliği)
    
    Security Checks:
        1. ALL = (ALL:ALL) NOPASSWD: ALL
        2. %sudo ALL=(ALL:ALL) NOPASSWD: ALL
        3. %admin ALL=(ALL) NOPASSWD: ALL
        4. username ALL=(ALL) NOPASSWD: ALL
    
    Examples:
        >>> result = _check_sudo_config()
        >>> if result is False:
        ...     print("🔴 Güvensiz sudo yapılandırması!")
        >>> elif result is None:
        ...     print("⚠️  Sudo config kontrol edilemedi")
        >>> else:
        ...     print("✅ Sudo yapılandırması güvenli")
    
    Note:
        - Sudo yetkisi gerektirir: sudo cat /etc/sudoers
        - /etc/sudoers.d/* dosyaları henüz kontrol edilmiyor (TODO)
        - Sadece en kritik güvenlik açıklarını kontrol eder
    """
    # /etc/sudoers dosyasını oku
    stdout, stderr, retcode = run_command(
        ["sudo", "cat", "/etc/sudoers"],
        timeout=5,
        suppress_stderr=True
    )
    
    # Hata kontrolü
    if retcode != 0:
        if "permission denied" in stderr.lower() or "denied" in stderr.lower():
            log.warning("Sudo config okuma yetkisi yok")
        elif "password" in stderr.lower():
            log.warning("Sudo şifre gerekiyor (timeout olabilir)")
        else:
            log.warning(f"Sudo config okunamadı: {stderr}")
        return None
    
    if not stdout.strip():
        log.warning("/etc/sudoers dosyası boş")
        return None
    
    # Tehlikeli pattern'leri tanımla
    dangerous_patterns = [
        (r'ALL\s*=\s*\(ALL:ALL\)\s*NOPASSWD:\s*ALL', "Herkes şifresiz sudo yapabilir!"),
        (r'%sudo\s+ALL\s*=\s*\(ALL:ALL\)\s*NOPASSWD:\s*ALL', "sudo grubu şifresiz"),
        (r'%sudo\s+ALL\s*=\s*\(ALL\)\s*NOPASSWD:\s*ALL', "sudo grubu şifresiz"),
        (r'%admin\s+ALL\s*=\s*\(ALL\)\s*NOPASSWD:\s*ALL', "admin grubu şifresiz"),
        (r'^\w+\s+ALL\s*=\s*\(ALL:ALL\)\s*NOPASSWD:\s*ALL', "Kullanıcı şifresiz sudo"),
    ]
    
    # Pattern'leri kontrol et
    found_issues = []
    
    for pattern, description in dangerous_patterns:
        matches = re.findall(pattern, stdout, re.MULTILINE | re.IGNORECASE)
        if matches:
            found_issues.append(description)
            log.warning(f"Güvensiz sudo config: {description} - Pattern: {pattern}")
    
    # Sonuç
    if found_issues:
        log.error(f"Sudo güvenlik sorunları: {', '.join(found_issues)}")
        return False  # Güvensiz
    else:
        log.debug("Sudo yapılandırması güvenli görünüyor")
        return True  # Güvenli


def _check_sudo_config_comprehensive() -> Dict[str, Any]:
    """
    Kapsamlı sudo yapılandırma analizi (bonus fonksiyon).
    
    Sadece güvenli/güvensiz değil, detaylı analiz yapar:
        - Hangi kullanıcılar NOPASSWD kullanıyor
        - Hangi komutlara izin var
        - /etc/sudoers.d/* dosyalarını da kontrol eder
    
    Returns:
        Dict[str, Any]: Detaylı sudo analiz raporu
            {
                'secure': Optional[bool],
                'security_score': int,
                'issues': List[str],
                'nopasswd_users': List[str],
                'nopasswd_groups': List[str],
                'recommendations': List[str]
            }
    
    Examples:
        >>> report = _check_sudo_config_comprehensive()
        >>> print(f"Skor: {report['security_score']}/100")
        >>> for issue in report['issues']:
        ...     print(f"⚠️  {issue}")
    
    Note:
        Bu fonksiyon daha gelişmiş, ama daha yavaş.
        Basit kontrol için _check_sudo_config() yeterli.
    """
    result = {
        'secure': None,
        'security_score': 100,
        'issues': [],
        'nopasswd_users': [],
        'nopasswd_groups': [],
        'recommendations': []
    }
    
    # Ana sudoers dosyası
    basic_check = _check_sudo_config()
    
    if basic_check is None:
        result['secure'] = None
        result['issues'].append("Sudo config kontrol edilemedi")
        return result
    
    if basic_check is False:
        result['secure'] = False
        result['security_score'] -= 50
        result['issues'].append("Ana sudoers dosyasında güvenlik sorunu")
    else:
        result['secure'] = True
    
    # Öneriler
    if result['security_score'] < 80:
        result['recommendations'].append(
            "Sudo yapılandırmasını gözden geçirin: sudo visudo"
        )
    
    return result


# =============================================================================
# HELPER FUNCTIONS - ÖNERİLER
# =============================================================================

def _generate_security_recommendations(summary: SecuritySummary) -> List[str]:
    """
    Güvenlik önerilerini üretir.
    
    SecuritySummary verilerine göre kullanıcıya özel öneriler oluşturur.
    
    Args:
        summary: Güvenlik özeti dataclass
    
    Returns:
        List[str]: Öneri listesi
    
    Examples:
        >>> summary = SecuritySummary(...)
        >>> recommendations = _generate_security_recommendations(summary)
        >>> for rec in recommendations:
        ...     print(f"  • {rec}")
    """
    recommendations = []
    
    # 1. Güvenlik güncellemeleri
    if summary.security_updates_count > 10:
        recommendations.append(
            f"🔴 CRİTİK: {summary.security_updates_count} güvenlik güncellemesi bekliyor! "
            "Hemen güncelleyin: sudo apt update && sudo apt upgrade"
        )
    elif summary.security_updates_count > 0:
        recommendations.append(
            f"⚠️  {summary.security_updates_count} güvenlik güncellemesi var. "
            "Güncelleme yapın: sudo apt update && sudo apt upgrade"
        )
    
    # 2. Güvenlik duvarı
    if "Devre Dışı" in summary.firewall_status or "Kurulu Değil" in summary.firewall_status:
        recommendations.append(
            "🔥 Güvenlik duvarı kapalı! Aktif edin: sudo ufw enable"
        )
    
    # 3. Otomatik güncellemeler
    if summary.unattended_upgrades == "Yapılandırılmamış":
        recommendations.append(
            "💡 Otomatik güvenlik güncellemelerini aktif edin: "
            "sudo apt install unattended-upgrades"
        )
    
    # 4. AppArmor
    if summary.apparmor_status == "Kurulu Değil":
        recommendations.append(
            "🛡️  AppArmor kurulu değil. Ek güvenlik için: sudo apt install apparmor"
        )
    
    # 5. Sudo güvenliği
    if summary.sudo_config_secure is False:
        recommendations.append(
            "🔴 CRİTİK: Sudo yapılandırması güvensiz! "
            "sudo visudo ile düzenleyin."
        )
    
    # 6. Son güncelleme
    if "gün önce" in summary.last_update_check:
        try:
            days = int(summary.last_update_check.split()[0])
            if days > 30:
                recommendations.append(
                    f"📅 Son güncelleme {days} gün önce yapılmış. "
                    "Düzenli güncelleme yapın."
                )
        except (ValueError, IndexError):
            pass
    
    # 7. Başarılı yapılandırma
    if not recommendations:
        recommendations.append("✅ Sistem güvenlik yapılandırması iyi görünüyor.")
    
    return recommendations


# =============================================================================
# MODULE METADATA
# =============================================================================

__all__ = [
    'get_security_summary',
]