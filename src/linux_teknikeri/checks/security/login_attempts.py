"""
Başarısız Giriş Denemesi Analiz Modülü
=======================================

Sistemdeki başarısız giriş denemelerini analiz eder ve brute-force
saldırı göstergelerini tespit eder.

Fonksiyonlar:
    check_failed_login_attempts()  - Ana fonksiyon (başarısız giriş analizi)

Özellikler:
    - journalctl ile SSH log analizi
    - Son N gün içindeki denemeler
    - IP adresi bazlı analiz
    - Kullanıcı adı bazlı analiz
    - Top saldırganlar listesi
    - Otomatik öneri üretimi

Veri Kaynağı:
    - journalctl _SYSTEMD_UNIT=ssh.service
    - /var/log/auth.log (alternatif)

Author: ozturu68
Version: 0.5.0
Date: 2025-11-01
License: MIT
"""

import re
import logging
from typing import Dict, List, Tuple, Any
from collections import Counter

# Local imports
from ...utils.command_runner import (
    run_command,
    is_command_available
)

# Logger
log = logging.getLogger(__name__)


# =============================================================================
# ANA FONKSİYON
# =============================================================================

def check_failed_login_attempts(days: int = 7) -> Dict[str, Any]:
    """
    Başarısız giriş denemelerini kontrol eder (brute-force saldırı göstergesi).
    
    journalctl kullanarak son N gün içindeki SSH başarısız giriş denemelerini
    analiz eder. IP adresi ve kullanıcı adı bazlı istatistikler üretir.
    
    Args:
        days (int): Kaç gün geriye bakılacak (varsayılan: 7)
    
    Returns:
        Dict[str, Any]: Başarısız giriş istatistikleri
            {
                'total_failed': int,                      # Toplam başarısız deneme
                'days_analyzed': int,                     # Analiz edilen gün sayısı
                'recent_failed': List[str],               # Son 20 deneme (log satırları)
                'top_ips': List[Tuple[str, int]],         # En çok deneme yapan IP'ler (top 10)
                'top_users': List[Tuple[str, int]],       # Hedef alınan kullanıcılar (top 10)
                'recommendations': List[str],             # Güvenlik önerileri
                'attack_detected': bool,                  # Saldırı tespit edildi mi?
                'critical_ips': List[Tuple[str, int]],    # Kritik IP'ler (>50 deneme)
            }
    
    Examples:
        >>> from linux_teknikeri.checks.security import check_failed_login_attempts
        >>> 
        >>> # Temel kullanım (son 7 gün)
        >>> failed = check_failed_login_attempts()
        >>> print(f"Toplam başarısız deneme: {failed['total_failed']}")
        Toplam başarısız deneme: 234
        >>> 
        >>> # En çok deneme yapan IP'ler
        >>> for ip, count in failed['top_ips'][:5]:
        ...     print(f"{ip}: {count} deneme")
        192.168.1.100: 150 deneme
        10.0.0.50: 45 deneme
        >>> 
        >>> # Hedef alınan kullanıcılar
        >>> for user, count in failed['top_users'][:5]:
        ...     print(f"{user}: {count} deneme")
        root: 180 deneme
        admin: 30 deneme
        >>> 
        >>> # Öneriler
        >>> for rec in failed['recommendations']:
        ...     print(f"  • {rec}")
        >>> 
        >>> # Son 30 gün analizi
        >>> failed_30d = check_failed_login_attempts(days=30)
    
    Performance:
        - Süre: 5-20 saniye (log boyutuna bağlı)
        - journalctl filtreli query kullanır (hızlı)
    
    Note:
        - Sudo yetkisi gerektirir (journalctl erişimi için)
        - SSH service log'larını okur
        - Hata durumunda boş istatistik döner
    
    Security:
        - Brute-force saldırı tespiti
        - Fail2ban kurulumu önerir
        - Kritik IP'leri tespit eder
        - UFW ile engelleme önerir
    
    See Also:
        - get_security_summary(): Genel güvenlik özeti
        - audit_ssh_config(): SSH yapılandırma denetimi
    """
    log.info(f"Başarısız giriş analizi başlatılıyor (son {days} gün)...")
    
    result = {
        'total_failed': 0,
        'days_analyzed': days,
        'recent_failed': [],
        'top_ips': [],
        'top_users': [],
        'recommendations': [],
        'attack_detected': False,
        'critical_ips': [],
    }
    
    # journalctl ile son X gün içindeki SSH loglarını kontrol et
    since_time = f"{days} days ago"
    
    try:
        stdout, stderr, retcode = run_command(
            ["sudo", "journalctl", "_SYSTEMD_UNIT=ssh.service", 
             "--since", since_time, "--no-pager"],
            timeout=30,  # Log büyükse zaman alabilir
            suppress_stderr=True
        )
        
        if retcode != 0:
            log.warning(f"journalctl komutu başarısız: {stderr}")
            result['recommendations'].append(
                "⚠️  Başarısız giriş kayıtları okunamadı (yetki gerekebilir)."
            )
            return result
        
        # Log analizi
        _analyze_ssh_logs(stdout, result)
        
        # Öneriler oluştur
        _generate_login_recommendations(result)
        
        log.info(f"Başarısız giriş analizi tamamlandı: {result['total_failed']} deneme")
    
    except Exception as e:
        log.error(f"Başarısız giriş analizi hatası: {e}", exc_info=True)
        result['recommendations'].append(f"❌ Hata: {str(e)}")
    
    return result


# =============================================================================
# HELPER FUNCTIONS - LOG ANALİZİ
# =============================================================================

def _analyze_ssh_logs(log_output: str, result: Dict[str, Any]) -> None:
    """
    SSH log çıktısını analiz eder.
    
    Args:
        log_output: journalctl çıktısı
        result: Doldurulan sonuç dictionary (in-place)
    
    Note:
        result dictionary'si in-place güncellenir.
    """
    # "Failed password" veya "authentication failure" satırlarını bul
    failed_lines = [
        line for line in log_output.split('\n')
        if 'Failed password' in line or 'authentication failure' in line
    ]
    
    result['total_failed'] = len(failed_lines)
    
    # Son 20 başarısız girişi sakla
    result['recent_failed'] = failed_lines[-20:]
    
    # IP adresleri ve kullanıcı adlarını çıkar
    ip_counts = Counter()
    user_counts = Counter()
    
    # IPv4 pattern: 192.168.1.1
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    
    # Kullanıcı pattern: "for user" veya "for invalid user"
    user_pattern = r'for (?:invalid user )?(\w+)(?: from|$)'
    
    for line in failed_lines:
        # IP adresleri
        ip_matches = re.findall(ip_pattern, line)
        for ip in ip_matches:
            # Localhost ve geçersiz IP'leri filtrele
            if ip not in ['0.0.0.0', '127.0.0.1', '255.255.255.255']:
                ip_counts[ip] += 1
        
        # Kullanıcı adları
        user_match = re.search(user_pattern, line)
        if user_match:
            user = user_match.group(1)
            user_counts[user] += 1
    
    # En çok deneme yapan IP'leri sırala (top 10)
    result['top_ips'] = ip_counts.most_common(10)
    
    # En çok hedef alınan kullanıcılar (top 10)
    result['top_users'] = user_counts.most_common(10)
    
    # Kritik IP'ler (>50 deneme)
    result['critical_ips'] = [
        (ip, count) for ip, count in ip_counts.items()
        if count > 50
    ]
    
    # Saldırı tespiti
    if result['total_failed'] > 100 or result['critical_ips']:
        result['attack_detected'] = True
        log.warning(f"Brute-force saldırısı tespit edildi! {result['total_failed']} deneme")


# =============================================================================
# HELPER FUNCTIONS - ÖNERİLER
# =============================================================================

def _generate_login_recommendations(result: Dict[str, Any]) -> None:
    """
    Başarısız giriş sonuçlarına göre öneriler üretir.
    
    Args:
        result: check_failed_login_attempts() sonuç dictionary (in-place)
    
    Note:
        result['recommendations'] listesi in-place güncellenir.
    """
    recommendations = []
    total = result['total_failed']
    days = result['days_analyzed']
    
    # 1. Genel değerlendirme
    if total > 1000:
        recommendations.append(
            f"🔴 CRİTİK: Son {days} günde {total} başarısız giriş denemesi! "
            "Ciddi bir brute-force saldırısı var."
        )
    elif total > 100:
        recommendations.append(
            f"⚠️  UYARI: Son {days} günde {total} başarısız giriş denemesi. "
            "Orta seviye güvenlik riski."
        )
    elif total > 10:
        recommendations.append(
            f"💡 BİLGİ: Son {days} günde {total} başarısız giriş denemesi. "
            "Normal seviyede."
        )
    else:
        recommendations.append(
            f"✅ İYİ: Son {days} günde sadece {total} başarısız giriş denemesi. "
            "Güvenlik durumu iyi."
        )
    
    # 2. Fail2ban önerisi
    if total > 100:
        if not is_command_available("fail2ban-client"):
            recommendations.append(
                "💡 Fail2ban kurulumu ÖNERİLİR: "
                "sudo apt install fail2ban"
            )
        else:
            recommendations.append(
                "✅ Fail2ban kurulu. "
                "Yapılandırmayı kontrol edin: sudo fail2ban-client status sshd"
            )
    
    # 3. En çok deneme yapan IP için özel öneri
    if result['top_ips']:
        top_ip, count = result['top_ips'][0]
        if count > 50:
            recommendations.append(
                f"⚠️  {top_ip} adresinden {count} başarısız deneme! "
                f"Bu IP'yi engelleyin: sudo ufw deny from {top_ip}"
            )
        elif count > 20:
            recommendations.append(
                f"💡 {top_ip} adresinden {count} deneme. "
                "Şüpheli aktivite, izlemeye devam edin."
            )
    
    # 4. Kritik IP'ler
    if result['critical_ips']:
        crit_count = len(result['critical_ips'])
        recommendations.append(
            f"🔴 {crit_count} IP adresi kritik seviyede deneme yaptı (>50 deneme). "
            "Bu IP'leri hemen engelleyin!"
        )
        
        # İlk 3 kritik IP'yi göster
        for ip, count in result['critical_ips'][:3]:
            recommendations.append(
                f"  • {ip}: {count} deneme - sudo ufw deny from {ip}"
            )
    
    # 5. Yaygın hedef kullanıcılar
    common_targets = ['root', 'admin', 'user', 'test', 'ubuntu', 'oracle']
    for user, count in result['top_users']:
        if user in common_targets and count > 20:
            recommendations.append(
                f"⚠️  '{user}' kullanıcısına {count} deneme yapılmış (yaygın hedef). "
                "SSH yapılandırmasını güçlendirin."
            )
            break  # Sadece bir uyarı yeterli
    
    # 6. SSH güvenlik önerileri
    if total > 50:
        recommendations.append(
            "🔒 SSH güvenlik önerileri:"
        )
        recommendations.append(
            "  • PasswordAuthentication no (SSH key kullanın)"
        )
        recommendations.append(
            "  • PermitRootLogin no (root girişini kapatın)"
        )
        recommendations.append(
            "  • Port 22 yerine özel port kullanın"
        )
        recommendations.append(
            "  • MaxAuthTries 3 (giriş denemesi sınırı)"
        )
    
    # 7. Başarılı durum
    if total == 0:
        recommendations.append(
            f"✅ Mükemmel! Son {days} günde hiç başarısız giriş denemesi yok."
        )
    
    result['recommendations'] = recommendations


# =============================================================================
# BONUS FUNCTIONS
# =============================================================================

def get_failed_login_summary(days: int = 7) -> str:
    """
    Başarısız giriş özetini metin olarak döndürür (bonus fonksiyon).
    
    Args:
        days: Kaç gün geriye bakılacak
    
    Returns:
        str: Özet metin (çok satırlı)
    
    Examples:
        >>> summary = get_failed_login_summary(days=7)
        >>> print(summary)
        Başarısız Giriş Özeti (Son 7 Gün)
        ===================================
        Toplam Deneme: 234
        Saldırı Tespit: Evet
        ...
    """
    result = check_failed_login_attempts(days)
    
    lines = [
        f"Başarısız Giriş Özeti (Son {days} Gün)",
        "=" * 50,
        f"Toplam Deneme: {result['total_failed']}",
        f"Saldırı Tespit: {'Evet' if result['attack_detected'] else 'Hayır'}",
        f"Kritik IP Sayısı: {len(result['critical_ips'])}",
        "",
        "En Çok Deneme Yapan IP'ler (Top 5):",
    ]
    
    for i, (ip, count) in enumerate(result['top_ips'][:5], 1):
        lines.append(f"  {i}. {ip}: {count} deneme")
    
    lines.append("")
    lines.append("Hedef Alınan Kullanıcılar (Top 5):")
    
    for i, (user, count) in enumerate(result['top_users'][:5], 1):
        lines.append(f"  {i}. {user}: {count} deneme")
    
    lines.append("")
    lines.append("Öneriler:")
    
    for rec in result['recommendations']:
        lines.append(f"  • {rec}")
    
    return "\n".join(lines)


def check_specific_ip(ip: str, days: int = 7) -> Dict[str, Any]:
    """
    Belirli bir IP adresinin aktivitesini kontrol eder (bonus fonksiyon).
    
    Args:
        ip: Kontrol edilecek IP adresi
        days: Kaç gün geriye bakılacak
    
    Returns:
        Dict[str, Any]: IP özet bilgisi
            {
                'ip': str,
                'total_attempts': int,
                'targeted_users': List[Tuple[str, int]],
                'is_critical': bool,
                'recommendation': str
            }
    
    Examples:
        >>> info = check_specific_ip("192.168.1.100")
        >>> print(f"{info['ip']}: {info['total_attempts']} deneme")
        >>> if info['is_critical']:
        ...     print(f"⚠️  {info['recommendation']}")
    """
    result = check_failed_login_attempts(days)
    
    ip_info = {
        'ip': ip,
        'total_attempts': 0,
        'targeted_users': [],
        'is_critical': False,
        'recommendation': ''
    }
    
    # IP'yi top_ips'te bul
    for ip_addr, count in result['top_ips']:
        if ip_addr == ip:
            ip_info['total_attempts'] = count
            break
    
    # Kritik mi?
    if ip_info['total_attempts'] > 50:
        ip_info['is_critical'] = True
        ip_info['recommendation'] = f"Bu IP'yi hemen engelleyin: sudo ufw deny from {ip}"
    elif ip_info['total_attempts'] > 20:
        ip_info['recommendation'] = "Şüpheli aktivite, izlemeye devam edin."
    elif ip_info['total_attempts'] > 0:
        ip_info['recommendation'] = "Normal seviyede aktivite."
    else:
        ip_info['recommendation'] = "Bu IP'den başarısız giriş denemesi yok."
    
    return ip_info


def get_attack_timeline(days: int = 7) -> List[Dict[str, Any]]:
    """
    Saldırı zaman çizelgesini oluşturur (bonus fonksiyon).
    
    Günlük bazda başarısız giriş denemelerini gösterir.
    
    Args:
        days: Kaç gün geriye bakılacak
    
    Returns:
        List[Dict[str, Any]]: Günlük deneme sayıları
            [
                {'date': '2025-11-01', 'attempts': 45},
                {'date': '2025-10-31', 'attempts': 30},
                ...
            ]
    
    Examples:
        >>> timeline = get_attack_timeline(days=7)
        >>> for day in timeline:
        ...     print(f"{day['date']}: {day['attempts']} deneme")
    
    Note:
        Bu fonksiyon daha karmaşık log parsing gerektirir.
        Şu an basit implementasyon (TODO: günlük ayrıştırma).
    """
    # TODO: journalctl'den günlük bazda parse et
    log.warning("get_attack_timeline() henüz tam implement edilmedi")
    return []


# =============================================================================
# MODULE METADATA
# =============================================================================

__all__ = [
    'check_failed_login_attempts',
    'get_failed_login_summary',
    'check_specific_ip',
    'get_attack_timeline',
]