"""
Sistem Güvenliği Analiz Modülü
==============================

Güvenlik güncellemeleri, güvenlik duvarı, açık portlar, SSH yapılandırması,
başarısız giriş denemeleri ve diğer güvenlik kontrollerini yapar.

Features:
    - Güvenlik güncellemesi kontrolü
    - Güvenlik duvarı (UFW/firewalld) durumu
    - AppArmor/SELinux durumu
    - Açık port ve dinleyen servis analizi
    - SSH yapılandırma denetimi
    - Başarısız giriş denemesi analizi (brute-force)
    - Otomatik güncelleme yapılandırması
    - Sudo yapılandırma kontrolü
    - Açık güvenlik açıkları (CVE) kontrolü

Author: ozturu68
Version: 0.4.0
Date: 2025-01-29
License: MIT
"""

import re
import os
import logging
from typing import Dict, List, Tuple, Optional, Any
from pathlib import Path
from datetime import datetime, timedelta
from collections import Counter
from dataclasses import dataclass, asdict

from ..utils.command_runner import (
    run_command,
    is_command_available,
    safe_command_output
)

# Logger
log = logging.getLogger(__name__)


# =============================================================================
# DATACLASS TANIMLARI
# =============================================================================

@dataclass
class SecuritySummary:
    """Güvenlik özeti veri sınıfı."""
    security_updates_count: int
    firewall_status: str
    apparmor_status: str
    selinux_status: str
    unattended_upgrades: str
    last_update_check: str
    sudo_config_secure: Optional[bool] = None
    open_ports_count: Optional[int] = None
    failed_login_attempts: Optional[int] = None
    recommendations: List[str] = None
    
    def __post_init__(self):
        if self.recommendations is None:
            self.recommendations = []
    
    def to_dict(self) -> Dict[str, Any]:
        """Dataclass'ı dictionary'e çevirir."""
        return asdict(self)


@dataclass
class PortInfo:
    """Port bilgisi veri sınıfı."""
    protocol: str
    address: str
    port: str
    process: str
    pid: Optional[int] = None
    user: Optional[str] = None
    is_privileged: bool = False  # Port < 1024
    
    def __post_init__(self):
        try:
            port_num = int(self.port)
            self.is_privileged = port_num < 1024
        except ValueError:
            pass
    
    def to_dict(self) -> Dict[str, Any]:
        """Dataclass'ı dictionary'e çevirir."""
        return asdict(self)


@dataclass
class SSHAudit:
    """SSH yapılandırma denetim sonucu."""
    config_exists: bool
    root_login_permitted: Optional[bool]
    password_auth_enabled: Optional[bool]
    empty_passwords_permitted: Optional[bool]
    ssh_protocol: Optional[str]
    port: str
    permit_user_environment: Optional[bool]
    x11_forwarding: Optional[bool]
    max_auth_tries: Optional[int]
    recommendations: List[str] = None
    risk_level: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL
    
    def __post_init__(self):
        if self.recommendations is None:
            self.recommendations = []
        self._calculate_risk_level()
    
    def _calculate_risk_level(self):
        """Risk seviyesini hesaplar."""
        if self.empty_passwords_permitted:
            self.risk_level = "CRITICAL"
        elif self.root_login_permitted and self.password_auth_enabled:
            self.risk_level = "HIGH"
        elif self.root_login_permitted or (self.password_auth_enabled and self.port == "22"):
            self.risk_level = "MEDIUM"
        else:
            self.risk_level = "LOW"
    
    def to_dict(self) -> Dict[str, Any]:
        """Dataclass'ı dictionary'e çevirir."""
        return asdict(self)


# =============================================================================
# GÜVENLİK ÖZETİ
# =============================================================================

def get_security_summary() -> Dict[str, Any]:
    """
    Sistem güvenliği hakkında genel özet bilgiler toplar.
    
    Kontrol Edilen:
        - Bekleyen güvenlik güncellemeleri
        - Güvenlik duvarı (UFW/firewalld) durumu
        - SELinux/AppArmor durumu
        - Otomatik güncelleme yapılandırması
        - Son güncelleme zamanı
        - Sudo yapılandırması
    
    Returns:
        Dict[str, Any]: Güvenlik özeti bilgileri
        
    Examples:
        >>> summary = get_security_summary()
        >>> if summary['security_updates_count'] > 0:
        ...     print(f"⚠️  {summary['security_updates_count']} güvenlik güncellemesi bekliyor!")
        >>> if summary['firewall_status'] != "Aktif":
        ...     print("🔥 Güvenlik duvarı kapalı!")
    """
    summary = SecuritySummary(
        security_updates_count=-1,
        firewall_status='Bilinmiyor',
        apparmor_status='Bilinmiyor',
        selinux_status='Bilinmiyor',
        unattended_upgrades='Bilinmiyor',
        last_update_check='Bilinmiyor'
    )
    
    # --- 1. GÜVENLİK GÜNCELLEMELERİ KONTROLÜ ---
    summary.security_updates_count = _check_security_updates()
    
    # --- 2. GÜVENLİK DUVARI (UFW/FIREWALLD) DURUMU ---
    summary.firewall_status = _check_firewall_status()
    
    # --- 3. APPARMOR DURUMU ---
    summary.apparmor_status = _check_apparmor_status()
    
    # --- 4. SELINUX DURUMU ---
    summary.selinux_status = _check_selinux_status()
    
    # --- 5. OTOMATİK GÜNCELLEMELER ---
    summary.unattended_upgrades = _check_unattended_upgrades()
    
    # --- 6. SON GÜNCELLEME KONTROLÜ ---
    summary.last_update_check = _get_last_update_time()
    
    # --- 7. SUDO YAPILANDIRMA KONTROLÜ ---
    summary.sudo_config_secure = _check_sudo_config()
    
    # --- 8. ÖNERİLER ---
    summary.recommendations = _generate_security_recommendations(summary)
    
    return summary.to_dict()


def _check_security_updates() -> int:
    """
    Bekleyen güvenlik güncellemelerini sayar.
    
    Returns:
        int: Güvenlik güncellemesi sayısı (-1 = tespit edilemedi)
    """
    # Yöntem 1: apt-check (Ubuntu/Debian)
    if os.path.exists("/usr/lib/update-notifier/apt-check"):
        stdout, stderr, retcode = run_command(
            ["/usr/lib/update-notifier/apt-check"],
            timeout=15
        )
        
        # apt-check çıktıyı stderr'e yazar (bug değil, özellik!)
        output = stderr if stderr else stdout
        
        if retcode == 0 and output:
            try:
                # Çıktı formatı: "paketsayısı;güvenliksayısı"
                parts = output.strip().split(';')
                if len(parts) >= 2:
                    return int(parts[1])
            except (ValueError, IndexError) as e:
                log.warning(f"apt-check çıktısı ayrıştırılamadı: {e}")
    
    # Yöntem 2: apt list --upgradable
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
        return len(security_lines)
    
    # Yöntem 3: apt-get -s upgrade (simulation)
    stdout, stderr, retcode = run_command(
        ["apt-get", "-s", "upgrade"],
        timeout=15,
        suppress_stderr=True
    )
    
    if retcode == 0:
        # "security" içeren paketleri say
        security_count = stdout.lower().count('security')
        return security_count
    
    log.warning("Güvenlik güncellemeleri kontrol edilemedi")
    return -1


def _check_firewall_status() -> str:
    """
    Güvenlik duvarı durumunu kontrol eder (UFW veya firewalld).
    
    Returns:
        str: Güvenlik duvarı durumu
    """
    # UFW kontrolü (Ubuntu/Debian)
    if is_command_available("ufw"):
        stdout, stderr, retcode = run_command(
            ["sudo", "ufw", "status"],
            timeout=5
        )
        
        if "not found" in stderr.lower():
            pass  # Kurulu değil, devam et
        elif retcode != 0 and ("password" in stderr.lower() or "denied" in stderr.lower()):
            return "Yetki Gerekli"
        elif "inactive" in stdout.lower() or "etkin değil" in stdout.lower():
            return "Devre Dışı (UFW)"
        elif "active" in stdout.lower() or "etkin" in stdout.lower():
            # Aktif kuralları say
            rule_count = stdout.lower().count('allow') + stdout.lower().count('deny')
            return f"Aktif (UFW, {rule_count} kural)"
    
    # firewalld kontrolü (RHEL/CentOS/Fedora)
    if is_command_available("firewall-cmd"):
        stdout, stderr, retcode = run_command(
            ["sudo", "firewall-cmd", "--state"],
            timeout=5
        )
        
        if retcode == 0 and "running" in stdout.lower():
            return "Aktif (firewalld)"
        elif retcode == 0 and "not running" in stdout.lower():
            return "Devre Dışı (firewalld)"
    
    # iptables kontrolü (son çare)
    if is_command_available("iptables"):
        stdout, stderr, retcode = run_command(
            ["sudo", "iptables", "-L", "-n"],
            timeout=5
        )
        
        if retcode == 0:
            # Eğer policy DROP veya REJECT varsa aktif
            if "DROP" in stdout or "REJECT" in stdout:
                return "Aktif (iptables)"
            else:
                return "Yapılandırılmamış (iptables)"
    
    return "Kurulu Değil"


def _check_apparmor_status() -> str:
    """
    AppArmor durumunu kontrol eder.
    
    Returns:
        str: AppArmor durumu
    """
    if not is_command_available("aa-status"):
        return "Kurulu Değil"
    
    stdout, stderr, retcode = run_command(
        ["sudo", "aa-status"],
        timeout=5,
        suppress_stderr=True
    )
    
    if retcode != 0:
        return "Kontrol Edilemedi"
    
    if "apparmor module is loaded" in stdout.lower():
        # Kaç profil yüklü?
        profiles_match = re.search(r'(\d+) profiles are loaded', stdout)
        enforce_match = re.search(r'(\d+) profiles are in enforce mode', stdout)
        
        if profiles_match and enforce_match:
            total = profiles_match.group(1)
            enforced = enforce_match.group(1)
            return f"Aktif ({enforced}/{total} profil enforce modda)"
        else:
            return "Aktif"
    
    return "Yüklü Değil"


def _check_selinux_status() -> str:
    """
    SELinux durumunu kontrol eder.
    
    Returns:
        str: SELinux durumu
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


def _check_unattended_upgrades() -> str:
    """
    Otomatik güncelleme yapılandırmasını kontrol eder.
    
    Returns:
        str: Otomatik güncelleme durumu
    """
    config_file = Path("/etc/apt/apt.conf.d/20auto-upgrades")
    
    if not config_file.exists():
        return "Yapılandırılmamış"
    
    try:
        content = config_file.read_text()
        
        # Unattended-Upgrade aktif mi?
        if 'APT::Periodic::Unattended-Upgrade "1"' in content:
            # Güvenlik güncellemeleri otomatik mi?
            if 'APT::Periodic::Update-Package-Lists "1"' in content:
                return "Aktif (Güvenlik + Paket Listesi)"
            else:
                return "Aktif (Sadece Güvenlik)"
        else:
            return "Pasif"
    
    except PermissionError:
        return "Kontrol Edilemedi (Yetki)"
    except Exception as e:
        log.error(f"Unattended-upgrades kontrolü başarısız: {e}")
        return "Hata"


def _get_last_update_time() -> str:
    """
    Son güncelleme zamanını tespit eder.
    
    Returns:
        str: Son güncelleme zamanı
    """
    apt_history = Path("/var/log/apt/history.log")
    
    if not apt_history.exists():
        return "Bilinmiyor"
    
    try:
        stdout, stderr, retcode = run_command(
            ["tail", "-n", "100", str(apt_history)],
            timeout=5
        )
        
        if retcode == 0:
            # Son Start-Date satırını bul
            dates = re.findall(r'Start-Date:\s*(.+)', stdout)
            if dates:
                last_date = dates[-1].strip()
                
                # Tarihi parse et ve kaç gün önce olduğunu hesapla
                try:
                    date_obj = datetime.strptime(last_date, '%Y-%m-%d  %H:%M:%S')
                    days_ago = (datetime.now() - date_obj).days
                    
                    if days_ago == 0:
                        return f"Bugün ({last_date})"
                    elif days_ago == 1:
                        return f"Dün ({last_date})"
                    else:
                        return f"{days_ago} gün önce ({last_date})"
                except ValueError:
                    return last_date
        
        return "Bilinmiyor"
    
    except Exception as e:
        log.error(f"Son güncelleme zamanı alınamadı: {e}")
        return "Hata"


def _check_sudo_config() -> bool:
    """
    Sudo yapılandırmasının güvenli olup olmadığını kontrol eder.
    
    Returns:
        bool: Güvenli ise True
    """
    # /etc/sudoers dosyasını kontrol et
    stdout, stderr, retcode = run_command(
        ["sudo", "cat", "/etc/sudoers"],
        timeout=5
    )
    
    if retcode != 0:
        return None  # Kontrol edilemedi
    
    # NOPASSWD: ALL gibi tehlikeli yapılandırmaları kontrol et
    dangerous_patterns = [
        r'ALL\s*=\s*\(ALL:ALL\)\s*NOPASSWD:\s*ALL',
        r'%sudo\s*ALL=\(ALL:ALL\)\s*NOPASSWD:\s*ALL'
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, stdout, re.IGNORECASE):
            return False
    
    return True


def _generate_security_recommendations(summary: SecuritySummary) -> List[str]:
    """
    Güvenlik önerilerini üretir.
    
    Args:
        summary: Güvenlik özeti
        
    Returns:
        List[str]: Öneri listesi
    """
    recommendations = []
    
    # Güvenlik güncellemeleri
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
    
    # Güvenlik duvarı
    if "Devre Dışı" in summary.firewall_status or "Kurulu Değil" in summary.firewall_status:
        recommendations.append(
            "🔥 Güvenlik duvarı kapalı! Aktif edin: "
            "sudo ufw enable"
        )
    
    # Otomatik güncellemeler
    if summary.unattended_upgrades == "Yapılandırılmamış":
        recommendations.append(
            "💡 Otomatik güvenlik güncellemelerini aktif edin: "
            "sudo apt install unattended-upgrades"
        )
    
    # AppArmor
    if summary.apparmor_status == "Kurulu Değil":
        recommendations.append(
            "🛡️  AppArmor kurulu değil. Ek güvenlik için: "
            "sudo apt install apparmor"
        )
    
    # Son güncelleme
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
    
    if not recommendations:
        recommendations.append("✅ Sistem güvenlik yapılandırması iyi görünüyor.")
    
    return recommendations


# =============================================================================
# AÇIK PORTLAR VE SERVİSLER
# =============================================================================

def get_listening_ports() -> List[Dict[str, Any]]:
    """
    Sistemde dinlemede olan (LISTEN) ağ portlarını listeler.
    
    Returns:
        List[Dict[str, Any]]: Her port için bilgi sözlüğü
    
    Examples:
        >>> ports = get_listening_ports()
        >>> for port in ports:
        ...     if port['is_privileged']:
        ...         print(f"Ayrıcalıklı port: {port['port']} - {port['process']}")
    
    Note:
        - ss komutu tercih edilir (daha hızlı ve modern)
        - Fallback olarak netstat kullanılır
        - Sudo yetkisi gerekebilir (process bilgisi için)
    """
    ports = []
    
    # ss komutu daha modern ve hızlıdır
    if is_command_available("ss"):
        stdout, stderr, retcode = run_command(
            ["sudo", "ss", "-tulpn"],
            timeout=10
        )
        
        if retcode != 0:
            log.error(f"ss komutu başarısız: {stderr}")
            return [{'protocol': 'HATA', 'address': '', 'port': '', 'process': stderr.strip()}]
        
        for line in stdout.strip().split('\n'):
            # İlk satır (başlık) atla
            if line.startswith('Netid') or line.startswith('State'):
                continue
            
            # ss çıktısı: Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
            parts = line.split()
            if len(parts) < 5:
                continue
            
            protocol = parts[0]  # tcp, udp
            local_addr = parts[4]  # 0.0.0.0:80
            
            # Adres ve portu ayır
            if ':' in local_addr:
                addr, port = local_addr.rsplit(':', 1)
                # IPv6 adreslerini temizle
                addr = addr.strip('[]')
            else:
                continue
            
            # İşlem adını ve PID'yi bul (varsa)
            process = ''
            pid = None
            user = None
            
            if len(parts) >= 7:
                process_info = parts[6]
                # Format: users:(("sshd",pid=1234,fd=3))
                proc_match = re.search(r'\("([^"]+)",pid=(\d+)', process_info)
                if proc_match:
                    process = proc_match.group(1)
                    pid = int(proc_match.group(2))
            
            port_info = PortInfo(
                protocol=protocol,
                address=addr,
                port=port,
                process=process,
                pid=pid,
                user=user
            )
            
            ports.append(port_info.to_dict())
    
    else:
        # Fallback: netstat kullan
        stdout, stderr, retcode = run_command(
            ["sudo", "netstat", "-tulpn"],
            timeout=10
        )
        
        if retcode != 0:
            return [{
                'protocol': 'HATA',
                'address': '',
                'port': '',
                'process': 'ss ve netstat komutu bulunamadı'
            }]
        
        for line in stdout.strip().split('\n'):
            if not line.startswith('tcp') and not line.startswith('udp'):
                continue
            
            parts = line.split()
            if len(parts) < 4:
                continue
            
            protocol = parts[0]
            local_addr = parts[3]
            
            if ':' in local_addr:
                addr, port = local_addr.rsplit(':', 1)
                addr = addr.strip('[]')
            else:
                continue
            
            process = parts[6] if len(parts) >= 7 else ''
            if '/' in process:
                process = process.split('/')[-1]
            
            port_info = PortInfo(
                protocol=protocol,
                address=addr,
                port=port,
                process=process
            )
            
            ports.append(port_info.to_dict())
    
    return ports


# =============================================================================
# SSH YAPILANDIRMA DENETİMİ
# =============================================================================

def audit_ssh_config() -> Dict[str, Any]:
    """
    SSH yapılandırmasını güvenlik açısından denetler.
    
    Kontrol Edilen:
        - Root girişi izni
        - Şifre ile giriş izni
        - Boş şifre izni
        - SSH protokol versiyonu
        - Port numarası
        - X11 forwarding
        - PermitUserEnvironment
        - MaxAuthTries
    
    Returns:
        Dict[str, Any]: SSH yapılandırma denetim sonuçları
    
    Examples:
        >>> audit = audit_ssh_config()
        >>> if audit['root_login_permitted']:
        ...     print("⚠️  Root girişi aktif - güvenlik riski!")
        >>> if audit['risk_level'] == 'CRITICAL':
        ...     print("🔴 CRİTİK güvenlik sorunu!")
    """
    ssh_config_path = Path("/etc/ssh/sshd_config")
    
    audit_result = SSHAudit(
        config_exists=False,
        root_login_permitted=None,
        password_auth_enabled=None,
        empty_passwords_permitted=None,
        ssh_protocol=None,
        port='22',
        permit_user_environment=None,
        x11_forwarding=None,
        max_auth_tries=None
    )
    
    if not ssh_config_path.exists():
        audit_result.recommendations.append(
            "ℹ️  SSH sunucusu kurulu değil veya yapılandırma dosyası bulunamadı."
        )
        return audit_result.to_dict()
    
    audit_result.config_exists = True
    
    try:
        config_content = ssh_config_path.read_text()
        
        # Root Login
        root_login_match = re.search(
            r'^\s*PermitRootLogin\s+(\w+)',
            config_content,
            re.MULTILINE | re.IGNORECASE
        )
        if root_login_match:
            value = root_login_match.group(1).lower()
            audit_result.root_login_permitted = (value == 'yes')
            
            if value == 'yes':
                audit_result.recommendations.append(
                    "🔴 CRİTİK: Root girişi aktif! "
                    "Düzeltin: PermitRootLogin no"
                )
            elif value in ['prohibit-password', 'without-password']:
                audit_result.recommendations.append(
                    "💡 Root sadece anahtar ile girebiliyor (iyi). "
                    "Daha güvenli: PermitRootLogin no"
                )
        else:
            audit_result.recommendations.append(
                "ℹ️  PermitRootLogin ayarı açıkça belirtilmemiş (varsayılan: prohibit-password)."
            )
        
        # Password Authentication
        password_auth_match = re.search(
            r'^\s*PasswordAuthentication\s+(\w+)',
            config_content,
            re.MULTILINE | re.IGNORECASE
        )
        if password_auth_match:
            value = password_auth_match.group(1).lower()
            audit_result.password_auth_enabled = (value == 'yes')
            
            if value == 'yes':
                audit_result.recommendations.append(
                    "⚠️  Şifre ile giriş aktif. "
                    "Daha güvenli: PasswordAuthentication no (SSH key kullanın)"
                )
        
        # Empty Passwords
        empty_passwords_match = re.search(
            r'^\s*PermitEmptyPasswords\s+(\w+)',
            config_content,
            re.MULTILINE | re.IGNORECASE
        )
        if empty_passwords_match:
            value = empty_passwords_match.group(1).lower()
            audit_result.empty_passwords_permitted = (value == 'yes')
            
            if value == 'yes':
                audit_result.recommendations.append(
                    "🔴 CRİTİK: Boş şifreler kabul ediliyor! "
                    "HEMEN KAPATIN: PermitEmptyPasswords no"
                )
        
        # Protocol
        protocol_match = re.search(
            r'^\s*Protocol\s+(\d)',
            config_content,
            re.MULTILINE | re.IGNORECASE
        )
        if protocol_match:
            audit_result.ssh_protocol = protocol_match.group(1)
            
            if audit_result.ssh_protocol == '1':
                audit_result.recommendations.append(
                    "🔴 CRİTİK: SSH Protocol 1 kullanılıyor! "
                    "Protocol 2 kullanın (daha güvenli)"
                )
        
        # Port
        port_match = re.search(
            r'^\s*Port\s+(\d+)',
            config_content,
            re.MULTILINE | re.IGNORECASE
        )
        if port_match:
            audit_result.port = port_match.group(1)
            
            if audit_result.port == '22':
                audit_result.recommendations.append(
                    "💡 SSH varsayılan port (22) kullanılıyor. "
                    "Özel port (ör: 2222) brute-force saldırılarını azaltabilir."
                )
        
        # X11 Forwarding
        x11_match = re.search(
            r'^\s*X11Forwarding\s+(\w+)',
            config_content,
            re.MULTILINE | re.IGNORECASE
        )
        if x11_match:
            value = x11_match.group(1).lower()
            audit_result.x11_forwarding = (value == 'yes')
            
            if value == 'yes':
                audit_result.recommendations.append(
                    "⚠️  X11 Forwarding aktif. Gerekliyse güvenlik riski!"
                )
        
        # PermitUserEnvironment
        user_env_match = re.search(
            r'^\s*PermitUserEnvironment\s+(\w+)',
            config_content,
            re.MULTILINE | re.IGNORECASE
        )
        if user_env_match:
            value = user_env_match.group(1).lower()
            audit_result.permit_user_environment = (value == 'yes')
            
            if value == 'yes':
                audit_result.recommendations.append(
                    "⚠️  PermitUserEnvironment aktif. Güvenlik riski!"
                )
        
        # MaxAuthTries
        max_tries_match = re.search(
            r'^\s*MaxAuthTries\s+(\d+)',
            config_content,
            re.MULTILINE | re.IGNORECASE
        )
        if max_tries_match:
            audit_result.max_auth_tries = int(max_tries_match.group(1))
            
            if audit_result.max_auth_tries > 3:
                audit_result.recommendations.append(
                    f"💡 MaxAuthTries çok yüksek ({audit_result.max_auth_tries}). "
                    "Öneri: MaxAuthTries 3"
                )
        
        # Genel öneriler
        if not audit_result.recommendations:
            audit_result.recommendations.append(
                "✅ SSH yapılandırması güvenli görünüyor."
            )
    
    except PermissionError:
        audit_result.recommendations.append(
            "⚠️  SSH yapılandırması okunamadı (yetki gerekli)."
        )
    except Exception as e:
        log.error(f"SSH yapılandırması okunamadı: {e}")
        audit_result.recommendations.append(f"Hata: {str(e)}")
    
    return audit_result.to_dict()


# =============================================================================
# BAŞARISIZ GİRİŞ DENEMELERİ (BRUTE-FORCE ANALİZİ)
# =============================================================================

def check_failed_login_attempts(days: int = 7) -> Dict[str, Any]:
    """
    Başarısız giriş denemelerini kontrol eder (brute-force saldırı göstergesi).
    
    Args:
        days: Kaç gün geriye bakılacak (varsayılan: 7)
    
    Returns:
        Dict[str, Any]: Başarısız giriş istatistikleri
    
    Examples:
        >>> failed = check_failed_login_attempts()
        >>> if failed['total_failed'] > 100:
        ...     print("⚠️  Çok sayıda başarısız giriş denemesi!")
        >>> for ip, count in failed['top_ips'][:5]:
        ...     print(f"{ip}: {count} deneme")
    """
    result = {
        'total_failed': 0,
        'recent_failed': [],
        'top_ips': [],
        'top_users': [],
        'recommendations': [],
        'days_analyzed': days
    }
    
    # journalctl ile son X gün içindeki SSH loglarını kontrol et
    since_time = f"{days} days ago"
    stdout, stderr, retcode = run_command(
        ["sudo", "journalctl", "_SYSTEMD_UNIT=ssh.service", "--since", since_time, "--no-pager"],
        timeout=20
    )
    
    if retcode != 0:
        result['recommendations'].append(
            "⚠️  Başarısız giriş kayıtları okunamadı (yetki gerekebilir)."
        )
        return result
    
    # "Failed password" satırlarını bul
    failed_lines = [
        line for line in stdout.split('\n')
        if 'Failed password' in line or 'authentication failure' in line
    ]
    
    result['total_failed'] = len(failed_lines)
    
    # Son 20 başarısız girişi sakla
    result['recent_failed'] = failed_lines[-20:]
    
    # IP adreslerini çıkar ve say
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ip_counts = Counter()
    user_counts = Counter()
    
    for line in failed_lines:
        # IP adresleri
        ip_matches = re.findall(ip_pattern, line)
        for ip in ip_matches:
            if ip != '0.0.0.0' and ip != '127.0.0.1':
                ip_counts[ip] += 1
        
        # Kullanıcı adları
        user_match = re.search(r'for (?:invalid user )?(\w+) from', line)
        if user_match:
            user_counts[user_match.group(1)] += 1
    
    # En çok deneme yapan IP'leri sırala
    result['top_ips'] = ip_counts.most_common(10)
    result['top_users'] = user_counts.most_common(10)
    
    # Öneriler
    if result['total_failed'] > 1000:
        result['recommendations'].append(
            f"🔴 CRİTİK: Son {days} günde {result['total_failed']} başarısız giriş denemesi!"
        )
        result['recommendations'].append(
            "💡 Fail2ban kurulumu ÖNERİLİR: sudo apt install fail2ban"
        )
    elif result['total_failed'] > 100:
        result['recommendations'].append(
            f"⚠️  Son {days} günde {result['total_failed']} başarısız giriş denemesi."
        )
        result['recommendations'].append(
            "💡 Fail2ban kurulumu önerilir: sudo apt install fail2ban"
        )
    
    # En çok deneme yapan IP için özel öneri
    if result['top_ips']:
        top_ip, count = result['top_ips'][0]
        if count > 50:
            result['recommendations'].append(
                f"⚠️  {top_ip} adresinden {count} başarısız deneme!"
            )
            result['recommendations'].append(
                f"💡 IP'yi engelleyin: sudo ufw deny from {top_ip}"
            )
    
    # Yaygın kullanıcı adları
    common_targets = ['root', 'admin', 'user', 'test']
    for user, count in result['top_users']:
        if user in common_targets and count > 20:
            result['recommendations'].append(
                f"⚠️  '{user}' kullanıcısına {count} deneme yapılmış (yaygın hedef)."
            )
    
    if result['total_failed'] == 0:
        result['recommendations'].append(
            "✅ Son 7 günde başarısız giriş denemesi yok."
        )
    
    return result


# =============================================================================
# ÖRNEK KULLANIM
# =============================================================================

if __name__ == "__main__":
    # Test
    import json
    
    logging.basicConfig(level=logging.DEBUG)
    
    print("=== Güvenlik Analizi Test ===\n")
    
    # 1. Güvenlik özeti
    print("1. Güvenlik Özeti:")
    summary = get_security_summary()
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    
    # 2. Açık portlar
    print("\n2. Açık Portlar:")
    ports = get_listening_ports()
    print(json.dumps(ports[:5], indent=2, ensure_ascii=False))
    
    # 3. SSH denetimi
    print("\n3. SSH Yapılandırma Denetimi:")
    ssh = audit_ssh_config()
    print(json.dumps(ssh, indent=2, ensure_ascii=False))
    
    # 4. Başarısız giriş denemeleri
    print("\n4. Başarısız Giriş Denemeleri:")
    failed = check_failed_login_attempts()
    print(json.dumps(failed, indent=2, ensure_ascii=False))
    
    print("\n=== Test Tamamlandı ===")