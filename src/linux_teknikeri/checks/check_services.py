import re
from ..utils.command_runner import run_command

def get_running_services():
    """
    Kategori 1: Aktif Çalışan Servisler
    `systemctl` komutunu daha güvenilir parametrelerle kullanarak listeler.
    """
    # --no-pager: Çıktıyı sayfalama yapmadan tek seferde ver.
    # --no-legend: Başlık ve alt bilgi satırlarını gösterme.
    # --plain: Çıktıdaki özel karakterleri (● gibi) basma.
    command = ["systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--no-legend", "--plain"]
    stdout, _, retcode = run_command(command)
    
    if retcode != 0:
        return [] # Hata durumunda boş liste döndürmek daha tutarlıdır.
        
    # Çıktı artık temiz olduğu için doğrudan ayrıştırabiliriz.
    services = [line.split()[0] for line in stdout.strip().split('\n') if line]
    return services

def get_failed_services():
    """
    Kategori 2: Hatalı Servisler
    `systemctl` komutunu daha güvenilir parametrelerle kullanarak 'failed' durumundaki servisleri tespit eder.
    """
    command = ["systemctl", "list-units", "--type=service", "--state=failed", "--no-pager", "--no-legend", "--plain"]
    stdout, _, retcode = run_command(command)
    
    if retcode != 0:
        return []
        
    failed_services = [line.split()[0] for line in stdout.strip().split('\n') if line]
    return failed_services

# --- YENİ UZMAN TEŞHİS FONKSİYONU ---
def get_services_with_errors(service_list):
    """
    Verilen servis listesini `journalctl` kullanarak kontrol eder ve son 24 saat
    içinde hata (error) kaydı oluşturmuş olan "şüpheli" servisleri döndürür.
    """
    problematic_services = []
    if not service_list:
        return []

    for service in service_list:
        # journalctl ile servisin son 24 saatlik kayıtlarını kontrol et.
        # --priority=3: Sadece "error" seviyesindeki kayıtları ara.
        # -n 1: Sadece 1 tane bulması yeterli, tüm logu aramasın (hız).
        # --quiet: Log içeriğini basma, sadece var olup olmadığını kontrol et.
        command = [
            "journalctl",
            "--unit", service,
            "--since", "24 hours ago",
            "--priority", "3",
            "-n", "1",
            "--quiet"
        ]
        stdout, _, _ = run_command(command)
        
        # Eğer stdout boş değilse, en az bir hata kaydı bulunmuştur.
        if stdout.strip():
            problematic_services.append(service)
            
    return problematic_services