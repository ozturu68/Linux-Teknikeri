from ..utils.command_runner import run_command
import re

def get_boot_blame(count: int = 10):
    """
    `systemd-analyze blame` komutunu kullanarak sistem açılışını en çok
    yavaşlatan servisleri ve ne kadar sürdüklerini tespit eder.

    Args:
        count (int, optional): Listelenecek en yavaş servis sayısı.
                               Varsayılan: 10.

    Returns:
        list[dict]: Her biri {'time': str, 'service': str} formatında olan
                    sözlüklerin bir listesi. Hata durumunda boş liste döner.
    """
    # Komut zinciri: `systemd-analyze blame` çıktısını al ve `head` ile ilk 'count' satırı seç.
    # Bu, tüm listeyi işlemekten daha verimlidir.
    command = f"systemd-analyze blame | head -n {count}"
    
    # Zincirleme komut olduğu için `use_shell=True` kullanıyoruz.
    # Bu komut genellikle çok hızlı çalışır, bu yüzden özel bir timeout gerekmez.
    stdout, stderr, retcode = run_command(command, use_shell=True)

    if retcode != 0:
        # Hata durumunda (örn: komut bulunamazsa) anlamlı bir mesaj döndür.
        error_message = stderr.strip() if stderr else "Komut bilinmeyen bir nedenle başarısız oldu."
        return [{'time': 'HATA', 'service': error_message}]

    boot_times = []
    lines = stdout.strip().split('\n')

    for line in lines:
        # Satır genellikle " 5.213s networking.service" formatındadır.
        # Baştaki ve sondaki boşlukları temizle.
        clean_line = line.strip()
        
        try:
            # İlk boşluktan itibaren ayır. İlk parça zaman, geri kalanı servis adıdır.
            time, service = clean_line.split(maxsplit=1)
            boot_times.append({
                'time': time,
                'service': service
            })
        except ValueError:
            # Beklenmedik bir satır formatıyla karşılaşılırsa bu satırı atla.
            continue
            
    return boot_times