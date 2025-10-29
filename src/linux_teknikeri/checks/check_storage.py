import re
from ..utils.command_runner import run_command

def check_smart_health():
    """
    Kategori 2: Disk Fiziksel Sağlık (S.M.A.R.T.) Analizi
    Sadece gerçek fiziksel diskleri kontrol eder, zram gibi sanal diskleri atlar.
    """
    # Önce diskleri bulalım
    stdout, stderr, retcode = run_command(["lsblk", "-dno", "NAME,TYPE"])
    
    if retcode != 0:
        return {
            "status": "KONTROL EDİLEMEDİ", 
            "failing_disks": [f"Diskler listelenemedi (lsblk komutu başarısız): {stderr.strip()}"]
        }

    # --- KRİTİK DÜZELTME ---
    # 'disk' tipindeki aygıtları al, ancak 'zram' içerenleri filtrele.
    disk_names = [
        line.split()[0] for line in stdout.strip().split('\n') 
        if 'disk' in line and 'zram' not in line
    ]
    
    if not disk_names:
        return {
            "status": "BİLGİ YOK", 
            "failing_disks": ["Kontrol edilecek S.M.A.R.T. uyumlu fiziksel disk bulunamadı."]
        }

    failing_disks = []
    all_ok = True

    for disk in disk_names:
        device_path = f"/dev/{disk}"
        # -H: Sadece sağlık durumunu kontrol et
        stdout, stderr, retcode = run_command(["sudo", "smartctl", "-H", device_path])

        # Komutun başarısız olması veya çıktının "PASSED" içermemesi durumu
        if retcode != 0 or ("PASSED" not in stdout.upper() and "OK" not in stdout.upper()):
            all_ok = False
            # Kullanıcıya daha anlaşılır bir hata/durum mesajı verelim
            if "unavailable" in stderr.lower():
                status_message = f"'{device_path}' -> S.M.A.R.T. desteklemiyor veya kullanılamıyor."
            elif retcode != 0:
                 status_message = f"'{device_path}' -> Kontrol edilemedi: {stderr.strip()}"
            else:
                # Başarılı ama "PASSED" değilse, durumu gösteren satırı bul
                status_line = next((line for line in stdout.split('\n') if "test result" in line), "Belirtilen bir sağlık sorunu var.")
                status_message = f"'{device_path}' -> {status_line.strip()}"
            
            failing_disks.append(status_message)

    if not all_ok:
        return {"status": "SORUNLU", "failing_disks": failing_disks}
    
    return {"status": "İYİ", "failing_disks": []}