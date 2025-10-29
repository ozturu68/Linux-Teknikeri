import re
from ..utils.command_runner import run_command

def get_security_summary():
    """
    Kategori 2: Güvenlik Özeti
    Bekleyen güvenlik güncellemelerini ve güvenlik duvarı (ufw) durumunu kontrol eder.
    """
    summary = {}
    stdout, stderr, retcode = run_command(["/usr/lib/update-notifier/apt-check"])
    if retcode == 0:
        try:
            summary['security_updates_count'] = int(stdout.split(';')[1])
        except (ValueError, IndexError):
            summary['security_updates_count'] = -1
    else:
        summary['security_updates_count'] = -1

    stdout, stderr, retcode = run_command(["sudo", "ufw", "status"])
    if "not found" in stderr.lower() or "bulunamadı" in stderr.lower():
        summary['firewall_status'] = "Kurulu Değil"
    elif "inactive" in stdout.lower() or "etkin değil" in stdout.lower():
        summary['firewall_status'] = "Devre Dışı"
    elif "active" in stdout.lower() or "etkin" in stdout.lower():
        summary['firewall_status'] = "Aktif"
    elif retcode != 0 and ("password" in stderr.lower() or "parola" in stderr.lower()):
        summary['firewall_status'] = "Yetki Gerekli"
    else:
        summary['firewall_status'] = "Bilinmiyor"
    return summary

def get_listening_ports():
    """
    Kategori 2: Ağ Dinleme Portları
    `ss -tulnp` komutunu kullanarak dışarıya açık portları listeler.
    """
    stdout, stderr, retcode = run_command(["sudo", "ss", "-tulnp"])
    if retcode != 0:
        return [{"protocol": "HATA", "address": f"Portlar listelenemedi: {stderr.strip()}", "port": "", "process": ""}]
    
    listening_ports = []
    lines = stdout.strip().split('\n')[1:]
    for line in lines:
        parts = line.split()
        if len(parts) < 5: continue
        protocol, local_address_port = parts[0], parts[4]
        if "0.0.0.0:" in local_address_port or "[::]:" in local_address_port:
            try:
                address, port = local_address_port.rsplit(':', 1)
                process_info = ""
                process_match = re.search(r'users:\(\("([^"]+)",', line)
                if process_match: process_info = process_match.group(1)
                listening_ports.append({"protocol": protocol.upper(), "address": address, "port": port, "process": process_info})
            except (ValueError, IndexError):
                continue
    return listening_ports

# --- YENİ "SSH GÜVENLİK DENETÇİSİ" FONKSİYONU ---
def audit_ssh_config(config_path="/etc/ssh/sshd_config"):
    """
    SSH sunucu yapılandırmasını analiz eder ve yaygın güvenlik zafiyetlerini raporlar.

    Args:
        config_path (str): Kontrol edilecek sshd_config dosyasının yolu.

    Returns:
        list[dict]: Her biri bir bulguyu temsil eden sözlüklerin listesi.
                    Bulgular {'level': str, 'finding': str, 'recommendation': str} formatındadır.
    """
    findings = []
    try:
        with open(config_path, 'r') as f:
            config_lines = f.readlines()
    except FileNotFoundError:
        # SSH sunucusu kurulu değilse bu bir hata değildir, sadece bilgilendirmedir.
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
            'recommendation': 'Bu kontrolü çalıştırmak için okuma izinlerine veya sudo yetkisine ihtiyaç var.'
        })
        return findings

    active_config = {}
    for line in config_lines:
        clean_line = line.strip()
        # Yorum satırlarını ve boş satırları atla
        if not clean_line or clean_line.startswith('#'):
            continue
        
        parts = clean_line.split(maxsplit=1)
        if len(parts) == 2:
            # Anahtarları küçük harfe çevirerek karşılaştırmayı kolaylaştır
            key, value = parts
            active_config[key.lower()] = value

    # --- GÜVENLİK KONTROLLERİ ---
    
    # 1. Root Girişi Kontrolü
    if active_config.get('permitrootlogin') == 'yes':
        findings.append({
            'level': 'KRİTİK',
            'finding': 'PermitRootLogin yes',
            'recommendation': "Root kullanıcısının doğrudan SSH erişimi son derece tehlikelidir. Bu değeri 'no' veya 'prohibit-password' olarak değiştirin."
        })

    # 2. Parola ile Giriş Kontrolü
    if active_config.get('passwordauthentication') == 'yes':
        findings.append({
            'level': 'UYARI',
            'finding': 'PasswordAuthentication yes',
            'recommendation': "Parola tabanlı kimlik doğrulama, kaba kuvvet (brute-force) saldırılarına açıktır. Mümkünse bu değeri 'no' yapın ve sadece SSH anahtarları kullanın."
        })
        
    # Eğer hiç kritik bulgu yoksa, güvenli olduğunu belirten bir mesaj ekle
    if not findings:
        findings.append({
            'level': 'İYİ',
            'finding': 'SSH yapılandırmasında yaygın bir zafiyet bulunamadı.',
            'recommendation': 'Yapılandırma temel güvenlik kontrollerini geçiyor.'
        })

    return findings