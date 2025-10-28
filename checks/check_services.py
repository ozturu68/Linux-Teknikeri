from utils.command_runner import run_command

def get_running_services():
    """
    Sistemde aktif olarak çalışan systemd servislerini listeler.
    
    Returns:
        list[str]: Çalışan servislerin isimlerini içeren bir liste.
    """
    # Komutumuz: Sadece 'service' tipindeki ve 'running' durumundaki birimleri listele.
    # '--no-legend' ve '--no-pager' çıktılarını temiz tutar.
    command = ["systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--no-pager"]
    
    stdout, stderr, returncode = run_command(command)
    
    if returncode != 0:
        # Eğer systemctl komutu hata verirse, boş bir liste ve bir uyarı döndürebiliriz.
        print(f"Uyarı: Servisler listelenemedi. Hata: {stderr}")
        return []

    running_services = []
    # Komut çıktısını satırlara ayırıyoruz.
    lines = stdout.strip().split('\n')
    
    for line in lines:
        # systemctl çıktısı boşluklarla ayrılmış sütunlardan oluşur.
        # İlk sütun servis adını içerir.
        parts = line.split()
        if parts:
            # systemctl bazen satır başına bir '●' karakteri koyar, bunu temizleyelim.
            service_name = parts[0].strip('●')
            running_services.append(service_name)
            
    return running_services
