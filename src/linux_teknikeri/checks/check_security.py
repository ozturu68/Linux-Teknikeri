"""
Sistem güvenliği analiz modülü.
Güvenlik güncellemeleri, güvenlik duvarı, açık portlar ve SSH yapılandırması kontrolü.
"""
import re
import os
import logging
from typing import Dict, List, Tuple
from ..utils.command_runner import run_command

log = logging.getLogger(__name__)


def get_security_summary() -> Dict[str, any]:
    """
    Sistem güvenliği hakkında genel özet bilgiler toplar.
    
    Kontrol Edilen:
    - Bekleyen güvenlik güncellemeleri
    - Güvenlik duvarı (UFW) durumu
    - SELinux/AppArmor durumu
    - Otomatik güncelleme yapılandırması
    
    Returns:
        Dict: Güvenlik özeti bilgileri
        
    Examples:
        >>> summary = get_security_summary()
        >>> if summary['security_updates_count'] > 0:
        ...     print(f"⚠️  {summary['security_updates_count']} güvenlik güncellemesi bekliyor!")
    """
    summary = {
        'security_updates_count': -1,
        'firewall_status': 'Bilinmiyor',
        'apparmor_status': 'Bilinmiyor',
        'selinux_status': 'Bilinmiyor',
        'unattended_upgrades': 'Bilinmiyor',
        'last_update_check': 'Bilinmiyor'
    }
    
    # --- 1. Güvenlik Güncellemeleri Kontrolü ---
    # Debian/Ubuntu sistemlerde apt-check kullanımı
    stdout, stderr, retcode = run_command(["/usr/lib/update-notifier/apt-check"], timeout=10)
    
    if retcode == 0 and stdout:
        # Çıktı formatı: "paketsayısı;güvenliksayısı"
        try:
            parts = stdout.strip().split(';')
            if len(parts) >= 2:
                summary['security_updates_count'] = int(parts[1])
        except (ValueError, IndexError) as e:
            log.warning(f"apt-check çıktısı ayrıştırılamadı: {e}")
            summary['security_updates_count'] = -1
    else:
        # apt-check yoksa, alternatif yöntem dene
        stdout, stderr, retcode = run_command(
            ["apt", "list", "--upgradable"], 
            timeout=10, 
            suppress_stderr=True
        )
        if retcode == 0:
            # "security" kelimesini içeren satırları say
            security_lines = [line for line in stdout.split('\n') if 'security' in line.lower()]
            summary['security_updates_count'] = len(security_lines)
    
    # --- 2. Güvenlik Duvarı (UFW) Durumu ---
    stdout, stderr, retcode = run_command(["sudo", "ufw", "status"], timeout=5)
    
    if "not found" in stderr.lower() or "bulunamadı" in stderr.lower():
        summary['firewall_status'] = "Kurulu Değil"
    elif retcode != 0 and ("password" in stderr.lower() or "parola" in stderr.lower()):
        summary['firewall_status'] = "Yetki Gerekli"
    elif "inactive" in stdout.lower() or "etkin değil" in stdout.lower():
        summary['firewall_status'] = "Devre Dışı"
    elif "active" in stdout.lower() or "etkin" in stdout.lower():
        summary['firewall_status'] = "Aktif"
        
        # Kural sayısını da al
        rule_count = stdout.lower().count('allow') + stdout.lower().count('deny')
        if rule_count > 0:
            summary['firewall_status'] += f" ({rule_count} kural)"
    else:
        summary['firewall_status'] = "Bilinmiyor"
    
    # --- 3. AppArmor Durumu ---
    stdout, stderr, retcode = run_command(["sudo", "aa-status", "--enabled"], timeout=5)
    if retcode == 0:
        summary['apparmor_status'] = "Aktif"
        
        # Profil sayısını al
        stdout_full, _, retcode_full = run_command(["sudo", "aa-status"], timeout=5)
        if retcode_full == 0:
            enforced = len(re.findall(r'\d+ profiles are in enforce mode', stdout_full))
            complain = len(re.findall(r'\d+ profiles are in complain mode', stdout_full))
            if enforced or complain:
                summary['apparmor_status'] += f" ({enforced} enforce, {complain} complain)"
    else:
        summary['apparmor_status'] = "Devre Dışı veya Yüklü Değil"
    
    # --- 4. SELinux Durumu ---
    stdout, stderr, retcode = run_command(["getenforce"], timeout=5)
    if retcode == 0 and stdout.strip():
        summary['selinux_status'] = stdout.strip()
    else:
        summary['selinux_status'] = "Yüklü Değil"
    
    # --- 5. Otomatik Güncelleme Yapılandırması ---
    if os.path.exists("/etc/apt/apt.conf.d/20auto-upgrades"):
        try:
            with open("/etc/apt/apt.conf.d/20auto-upgrades", 'r') as f:
                content = f.read()
                if 'APT::Periodic::Unattended-Upgrade "1"' in content:
                    summary['unattended_upgrades'] = "Etkin"
                else:
                    summary['unattended_upgrades'] = "Devre Dışı"
        except (PermissionError, IOError):
            summary['unattended_upgrades'] = "Kontrol Edilemedi"
    else:
        summary['unattended_upgrades'] = "Yapılandırılmamış"
    
    # --- 6. Son Güncelleme Kontrolü ---
    # /var/lib/apt/periodic/update-success-stamp dosyasının tarihine bak
    stamp_file = "/var/lib/apt/periodic/update-success-stamp"
    if os.path.exists(stamp_file):
        try:
            import datetime
            mtime = os.path.getmtime(stamp_file)
            last_update = datetime.datetime.fromtimestamp(mtime)
            days_ago = (datetime.datetime.now() - last_update).days
            
            if days_ago == 0:
                summary['last_update_check'] = "Bugün"
            elif days_ago == 1:
                summary['last_update_check'] = "Dün"
            else:
                summary['last_update_check'] = f"{days_ago} gün önce"
        except Exception as e:
            log.warning(f"Son güncelleme zamanı okunamadı: {e}")
    
    return summary


def get_listening_ports() -> List[Dict[str, str]]:
    """
    Dışarıya açık olan (listening) TCP ve UDP portlarını listeler.
    
    Özellikle 0.0.0.0 ve :: (tüm arayüzler) üzerinde dinleyen portları gösterir.
    Bu portlar internetten erişilebilir olabilir!
    
    Returns:
        List[Dict]: Her port için {'protocol', 'address', 'port', 'process'} bilgileri
        
    Examples:
        >>> ports = get_listening_ports()
        >>> for port in ports:
        ...     print(f"{port['protocol']} port {port['port']} açık ({port['process']})")
    """
    stdout, stderr, retcode = run_command(["sudo", "ss", "-tulnp"], timeout=10)
    
    if retcode != 0:
        log.error(f"ss komutu başarısız: {stderr}")
        return [{
            "protocol": "HATA",
            "address": f"Portlar listelenemedi: {stderr.strip()[:100]}",
            "port": "",
            "process": ""
        }]
    
    listening_ports = []
    lines = stdout.strip().split('\n')
    
    # Başlık satırını atla
    if len(lines) > 1:
        lines = lines[1:]
    
    for line in lines:
        parts = line.split()
        if len(parts) < 5:
            continue
        
        protocol = parts[0]
        local_address_port = parts[4]
        
        # Sadece dışarıya açık portları al (0.0.0.0 veya ::)
        if "0.0.0.0:" in local_address_port or "[::]:" in local_address_port or "*:" in local_address_port:
            try:
                # Adres ve port ayırma
                if local_address_port.startswith('['):
                    # IPv6 formatı: [::]:port
                    address, port = local_address_port.rsplit(']:', 1)
                    address = address + ']'
                else:
                    # IPv4 formatı: 0.0.0.0:port
                    address, port = local_address_port.rsplit(':', 1)
                
                # Process bilgisini bul
                process_info = "N/A"
                process_match = re.search(r'users:\(\("([^"]+)",', line)
                if process_match:
                    process_info = process_match.group(1)
                
                listening_ports.append({
                    "protocol": protocol.upper(),
                    "address": address,
                    "port": port,
                    "process": process_info
                })
            except (ValueError, IndexError) as e:
                log.warning(f"Port satırı ayrıştırılamadı: {line[:50]} - {e}")
                continue
    
    return listening_ports


def get_common_port_info(port_number: str) -> Dict[str, str]:
    """
    Yaygın port numaralarının ne için kullanıldığını açıklar.
    
    Args:
        port_number: Port numarası (string)
    
    Returns:
        Dict: {'service': str, 'description': str, 'risk_level': str}
    """
    common_ports = {
        "21": {"service": "FTP", "description": "Dosya transferi", "risk_level": "YÜKSEK (şifresiz)"},
        "22": {"service": "SSH", "description": "Güvenli uzak erişim", "risk_level": "ORTA"},
        "23": {"service": "Telnet", "description": "Uzak terminal", "risk_level": "KRİTİK (şifresiz)"},
        "25": {"service": "SMTP", "description": "E-posta gönderme", "risk_level": "ORTA"},
        "53": {"service": "DNS", "description": "Alan adı çözümleme", "risk_level": "DÜŞÜK"},
        "80": {"service": "HTTP", "description": "Web sunucusu", "risk_level": "ORTA (şifresiz)"},
        "110": {"service": "POP3", "description": "E-posta alma", "risk_level": "YÜKSEK (şifresiz)"},
        "143": {"service": "IMAP", "description": "E-posta alma", "risk_level": "YÜKSEK (şifresiz)"},
        "443": {"service": "HTTPS", "description": "Güvenli web sunucusu", "risk_level": "DÜŞÜK"},
        "445": {"service": "SMB", "description": "Windows dosya paylaşımı", "risk_level": "YÜKSEK"},
        "3306": {"service": "MySQL", "description": "Veritabanı", "risk_level": "KRİTİK"},
        "5432": {"service": "PostgreSQL", "description": "Veritabanı", "risk_level": "KRİTİK"},
        "6379": {"service": "Redis", "description": "Cache/DB", "risk_level": "KRİTİK"},
        "8080": {"service": "HTTP-Alt", "description": "Alternatif web portu", "risk_level": "ORTA"},
        "27017": {"service": "MongoDB", "description": "NoSQL veritabanı", "risk_level": "KRİTİK"},
    }
    
    return common_ports.get(port_number, {
        "service": "Bilinmiyor",
        "description": f"Port {port_number}",
        "risk_level": "BİLİNMİYOR"
    })


def audit_ssh_config(config_path: str = "/etc/ssh/sshd_config") -> List[Dict[str, str]]:
    """
    SSH sunucu yapılandırmasını detaylı olarak analiz eder ve güvenlik sorunlarını tespit eder.
    
    Kontrol Edilen:
    - Root girişi izni
    - Parola ile kimlik doğrulama
    - Boş parola izni
    - X11 forwarding
    - Port numarası (varsayılan 22 kullanılıyor mu?)
    - SSH protokol versiyonu
    - Maksimum kimlik doğrulama denemesi
    
    Args:
        config_path: SSH yapılandırma dosyasının yolu
    
    Returns:
        List[Dict]: Her bulgu için {'level', 'finding', 'recommendation'} içeren sözlükler
        
    Examples:
        >>> findings = audit_ssh_config()
        >>> critical = [f for f in findings if f['level'] == 'KRİTİK']
        >>> if critical:
        ...     print(f"⚠️  {len(critical)} kritik güvenlik sorunu bulundu!")
    """
    findings = []
    
    try:
        with open(config_path, 'r') as f:
            config_lines = f.readlines()
    except FileNotFoundError:
        findings.append({
            'level': 'BİLGİ',
            'finding': 'SSH sunucusu (sshd) kurulu değil veya yapılandırma dosyası bulunamadı.',
            'recommendation': 'Eğer bu makineye uzaktan erişim gerekmiyorsa bu durum normaldir.'
        })
        return findings
    except PermissionError:
        findings.append({
            'level': 'HATA',
            'finding': f"SSH yapılandırma dosyası okunamadı: '{config_path}'",
            'recommendation': 'Bu kontrolü çalıştırmak için sudo yetkisi gerekiyor.'
        })
        return findings
    
    # Aktif yapılandırmayı parse et (yorum satırlarını atla)
    active_config = {}
    for line in config_lines:
        clean_line = line.strip()
        
        # Yorum satırlarını ve boş satırları atla
        if not clean_line or clean_line.startswith('#'):
            continue
        
        parts = clean_line.split(maxsplit=1)
        if len(parts) == 2:
            key, value = parts
            # Anahtarları küçük harfe çevir (case-insensitive)
            active_config[key.lower()] = value.lower()
    
    # --- GÜVENLİK KONTROLLERİ ---
    
    # 1. Root Girişi Kontrolü (EN ÖNEMLİ!)
    root_login = active_config.get('permitrootlogin', 'yes')  # Varsayılan genellikle 'yes'
    if root_login == 'yes':
        findings.append({
            'level': 'KRİTİK',
            'finding': 'PermitRootLogin yes',
            'recommendation': (
                "Root kullanıcısının doğrudan SSH erişimi SON DERECE TEHLİKELİDİR! "
                "Saldırganlar root şifresini kırmaya çalışır. "
                "Çözüm: Dosyada 'PermitRootLogin no' veya 'PermitRootLogin prohibit-password' yapın."
            )
        })
    elif root_login == 'prohibit-password':
        findings.append({
            'level': 'İYİ',
            'finding': 'PermitRootLogin prohibit-password',
            'recommendation': 'Root girişi sadece SSH anahtarı ile yapılabilir. Bu güvenli bir ayardır.'
        })
    
    # 2. Parola ile Giriş Kontrolü
    password_auth = active_config.get('passwordauthentication', 'yes')
    if password_auth == 'yes':
        findings.append({
            'level': 'UYARI',
            'finding': 'PasswordAuthentication yes',
            'recommendation': (
                "Parola tabanlı kimlik doğrulama, kaba kuvvet (brute-force) saldırılarına AÇIKTIR. "
                "Önerilen: SSH anahtarları kullanın ve bu değeri 'no' yapın. "
                "Komut: ssh-keygen ile anahtar oluşturun, ssh-copy-id ile sunucuya kopyalayın."
            )
        })
    
    # 3. Boş Parola İzni
    empty_password = active_config.get('permitemptypasswords', 'no')
    if empty_password == 'yes':
        findings.append({
            'level': 'KRİTİK',
            'finding': 'PermitEmptyPasswords yes',
            'recommendation': (
                "BOŞ PAROLA İLE GİRİŞE İZİN VERİLİYOR! Bu büyük bir güvenlik açığıdır. "
                "Hemen 'PermitEmptyPasswords no' yapın."
            )
        })
    
    # 4. X11 Forwarding
    x11_forwarding = active_config.get('x11forwarding', 'no')
    if x11_forwarding == 'yes':
        findings.append({
            'level': 'DÜŞÜK',
            'finding': 'X11Forwarding yes',
            'recommendation': (
                "X11 yönlendirmesi etkin. Gereksizse kapatın (X11Forwarding no). "
                "Grafik arayüzü aktarmaya ihtiyacınız yoksa güvenlik riski taşır."
            )
        })
    
    # 5. Port Kontrolü
    ssh_port = active_config.get('port', '22')
    if ssh_port == '22':
        findings.append({
            'level': 'BİLGİ',
            'finding': 'SSH varsayılan port (22) kullanılıyor',
            'recommendation': (
                "Otomatik saldırıları azaltmak için SSH portunu değiştirmeyi düşünün (örn: 2222). "
                "Not: Bu 'security through obscurity' yöntemidir, tek başına yeterli değildir."
            )
        })
    
    # 6. SSH Protokol Versiyonu
    protocol = active_config.get('protocol', '2')
    if '1' in protocol:
        findings.append({
            'level': 'KRİTİK',
            'finding': f'SSH Protocol {protocol} kullanılıyor',
            'recommendation': (
                "SSH Protocol 1 GÜVENLİ DEĞİLDİR ve artık kullanılmamalıdır. "
                "Sadece Protocol 2 kullanın: 'Protocol 2'"
            )
        })
    
    # 7. Maksimum Kimlik Doğrulama Denemesi
    max_auth_tries = active_config.get('maxauthtries', '6')
    try:
        if int(max_auth_tries) > 3:
            findings.append({
                'level': 'DÜŞÜK',
                'finding': f'MaxAuthTries {max_auth_tries}',
                'recommendation': (
                    "Çok fazla deneme hakkı var. Kaba kuvvet saldırılarını zorlaştırmak için "
                    "3 veya daha az yapın: 'MaxAuthTries 3'"
                )
            })
    except ValueError:
        pass
    
    # 8. Kullanıcı/Grup Kısıtlamaları
    allow_users = active_config.get('allowusers')
    allow_groups = active_config.get('allowgroups')
    
    if not allow_users and not allow_groups:
        findings.append({
            'level': 'BİLGİ',
            'finding': 'Kullanıcı kısıtlaması yok',
            'recommendation': (
                "TÜM sistem kullanıcıları SSH ile giriş yapabilir. "
                "Güvenliği artırmak için sadece belirli kullanıcılara izin verin: "
                "'AllowUsers kullanici1 kullanici2' veya 'AllowGroups ssh-users'"
            )
        })
    
    # 9. Idle Timeout
    client_alive_interval = active_config.get('clientaliveinterval', '0')
    if client_alive_interval == '0':
        findings.append({
            'level': 'DÜŞÜK',
            'finding': 'Boşta kalma zaman aşımı ayarlanmamış',
            'recommendation': (
                "Uzun süre boşta kalan SSH oturumları güvenlik riski taşır. "
                "Ayar örneği: 'ClientAliveInterval 300' (5 dakika)"
            )
        })
    
    # Eğer hiç kritik/uyarı bulgu yoksa
    if not any(f['level'] in ['KRİTİK', 'UYARI'] for f in findings):
        findings.append({
            'level': 'İYİ',
            'finding': 'SSH yapılandırması temel güvenlik kontrollerini geçiyor',
            'recommendation': 'Mevcut yapılandırma kabul edilebilir güvenlik seviyesinde.'
        })
    
    return findings


def check_failed_login_attempts() -> Dict[str, any]:
    """
    Son başarısız giriş denemelerini analiz eder (bruteforce tespiti).
    
    Returns:
        Dict: Başarısız giriş istatistikleri
        
    Examples:
        >>> attempts = check_failed_login_attempts()
        >>> if attempts['total'] > 100:
        ...     print("⚠️  Çok sayıda başarısız giriş denemesi tespit edildi!")
    """
    result = {
        'total': 0,
        'by_user': {},
        'by_ip': {},
        'recent_attacks': []
    }
    
    # lastb komutu ile başarısız girişleri al
    stdout, stderr, retcode = run_command(["sudo", "lastb", "-n", "100"], timeout=10)
    
    if retcode == 0 and stdout:
        lines = stdout.strip().split('\n')
        
        for line in lines:
            if not line.strip() or line.startswith('btmp'):
                continue
            
            parts = line.split()
            if len(parts) >= 3:
                username = parts[0]
                ip = parts[2] if len(parts) > 2 else 'unknown'
                
                result['total'] += 1
                result['by_user'][username] = result['by_user'].get(username, 0) + 1
                result['by_ip'][ip] = result['by_ip'].get(ip, 0) + 1
        
        # En çok deneme yapan IP'leri bul
        if result['by_ip']:
            sorted_ips = sorted(result['by_ip'].items(), key=lambda x: x[1], reverse=True)
            result['recent_attacks'] = [
                {'ip': ip, 'attempts': count} 
                for ip, count in sorted_ips[:5]  # En çok deneme yapan 5 IP
            ]
    
    return result


def get_sudo_users() -> List[str]:
    """
    Sudo yetkisi olan kullanıcıları listeler.
    
    Returns:
        List[str]: Sudo grubundaki kullanıcı listesi
    """
    stdout, stderr, retcode = run_command(["getent", "group", "sudo"], timeout=5)
    
    if retcode == 0 and stdout:
        # Çıktı formatı: "sudo:x:27:user1,user2,user3"
        parts = stdout.strip().split(':')
        if len(parts) >= 4:
            users = parts[3].split(',')
            return [u.strip() for u in users if u.strip()]
    
    return []


def check_world_writable_files(paths: List[str] = None) -> List[str]:
    """
    Herkes tarafından yazılabilir (world-writable) dosyaları arar.
    Bu dosyalar güvenlik riski taşır!
    
    Args:
        paths: Aranacak dizinler listesi. Varsayılan: ['/etc', '/usr/local/bin']
    
    Returns:
        List[str]: Tehlikeli dosyaların yolları
    """
    if paths is None:
        paths = ['/etc', '/usr/local/bin']
    
    dangerous_files = []
    
    for path in paths:
        if not os.path.exists(path):
            continue
        
        # find komutu ile world-writable dosyaları bul
        command = f"find {path} -type f -perm -002 2>/dev/null"
        stdout, _, retcode = run_command(command, use_shell=True, timeout=30)
        
        if retcode == 0 and stdout:
            files = [f.strip() for f in stdout.split('\n') if f.strip()]
            dangerous_files.extend(files)
    
    return dangerous_files[:20]  # İlk 20 sonucu döndür