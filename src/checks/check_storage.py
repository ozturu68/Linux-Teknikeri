import re
from utils.command_runner import run_command

def check_smart_health():
    """
    Kategori 2: Disk S.M.A.R.T. Sağlık Durumu
    `lsblk` ile ana, FİZİKSEL diskleri bulur (loop ve zram gibi sanal aygıtları filtreler)
    ve `smartctl` ile her birinin S.M.A.R.T. sağlık durumunu kontrol eder.

    Returns:
        dict: 'status' (İYİ veya SORUNLU) ve 'failing_disks' (sorunlu disklerin listesi)
              içeren bir sözlük.
    """
    # Önce smartctl aracının kurulu olup olmadığını kontrol et
    _, _, retcode = run_command(["which", "smartctl"])
    if retcode != 0:
        return {
            "status": "BİLİNMİYOR",
            "failing_disks": ["'smartmontools' paketi kurulu değil. S.M.A.R.T. durumu kontrol edilemedi."]
        }
        
    # --- GÜNCELLENMİŞ KOMUT ---
    # Sadece ana diskleri al, bölümleri atla (-d) ve en önemlisi,
    # 'loop' veya 'zram' ile başlayan aygıtları filtrele.
    # `sh -c` kullanımı, pipe (|) gibi shell özelliklerini kullanmamızı sağlar.
    command = "lsblk -dno NAME | grep -vE '^(loop|zram)'"
    stdout, stderr, retcode = run_command(["sh", "-c", command])
    
    if retcode != 0 and not stdout: # Komut hata verdi VE HİÇ çıktı üretmediyse
        return {
            "status": "HATA",
            "failing_disks": ["Fiziksel diskler listelenemedi."]
        }

    devices = stdout.strip().split('\n')
    if not devices or (len(devices) == 1 and not devices[0]):
         return {
            "status": "HATA",
            "failing_disks": ["Analiz edilecek fiziksel disk bulunamadı."]
        }

    failing_disks = []

    for device in devices:
        device_path = f"/dev/{device}"
        _, smart_stderr, smart_retcode = run_command(["sudo", "smartctl", "-H", device_path])

        if smart_retcode != 0 and "sudo: a password is required" in smart_stderr:
            return {
                "status": "YETKİ GEREKLİ",
                "failing_disks": [
                    f"'smartctl' komutu için 'sudo' yetkisi gerekiyor.",
                    "Bu kontrolün otomatik çalışması için 'sudoers' yapılandırması gerekebilir."
                ]
            }

        if (smart_retcode & 32) or (smart_retcode & 16) or (smart_retcode & 8) or (smart_retcode & 4) or (smart_retcode & 2) or (smart_retcode & 1):
             failing_disks.append(f"Disk: {device_path} - S.M.A.R.T. durumu BAŞARISIZ!")

    if failing_disks:
        return {"status": "SORUNLU", "failing_disks": failing_disks}
    else:
        return {"status": "İYİ", "failing_disks": []}