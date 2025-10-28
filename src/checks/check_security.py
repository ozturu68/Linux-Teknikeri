import re
from utils.command_runner import run_command

def get_security_summary():
    """
    Kategori 3: Güvenlik Denetimi
    Bekleyen güvenlik güncellemelerini ve güvenlik duvarı durumunu kontrol eder.
    
    Returns:
        dict: 'security_updates_count' ve 'firewall_status' anahtarlarını içeren bir sözlük.
    """
    summary = {
        "security_updates_count": 0,
        "firewall_status": "Bilinmiyor"
    }

    # 1. Bekleyen Güvenlik Güncellemeleri
    # 'apt list --upgradable' komutunu çalıştır, stderr'i /dev/null'a yönlendirerek
    # "WARNING: apt does not have a stable CLI interface" uyarısını gizle.
    stdout, _, retcode = run_command(["apt", "list", "--upgradable"], suppress_stderr=True)
    
    if retcode == 0:
        lines = stdout.strip().split('\n')
        count = 0
        # Çıktıdaki her satırı analiz et
        for line in lines:
            # Sadece 'security' kelimesini içeren satırları say. Bu, güvenlik yamalarını hedefler.
            # Örnek: ... [amd64,upgradable to: ...] (jammy-security)
            if 'security' in line:
                count += 1
        summary["security_updates_count"] = count
    else:
        # Komut hata verirse, bir sorun olduğunu belirtmek için -1 kullanıyoruz.
        summary["security_updates_count"] = -1 

    # 2. Güvenlik Duvarı (Firewall) Durumu
    # 'ufw' aracının kurulu olup olmadığını kontrol et
    _, _, ufw_exists_retcode = run_command(["which", "ufw"])
    if ufw_exists_retcode == 0:
        # ufw kurulu, durumunu kontrol et. sudo gerektirir.
        stdout, stderr, retcode = run_command(["sudo", "ufw", "status"])
        
        if "sudo: a password is required" in stderr:
            summary["firewall_status"] = "Yetki Gerekli"
        elif retcode == 0:
            if "Status: active" in stdout:
                summary["firewall_status"] = "Aktif"
            elif "Status: inactive" in stdout:
                summary["firewall_status"] = "Devre Dışı"
    else:
        summary["firewall_status"] = "Kurulu Değil"
        
    return summary