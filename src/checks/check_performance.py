import re
from utils.command_runner import run_command

def get_top_processes(count: int = 5) -> list[dict]:
    """
    Kategori 4: Yüksek Kaynak Tüketen İşlemler
    `ps` komutunu kullanarak CPU ve Bellek kullanımına göre en çok kaynak
    tüketen işlemleri listeler.

    Args:
        count (int, optional): Listelenecek işlem sayısı. Defaults to 5.

    Returns:
        list[dict]: Her biri bir işlemi temsil eden ve 'user', 'cpu', 'mem', 'command'
                    anahtarlarını içeren sözlüklerin bir listesi.
    """
    # --sort=-%cpu,-%mem: Önce CPU'ya, sonra Belleğe göre azalan şekilde sırala
    # aux: tüm kullanıcıların işlemlerini göster
    command = ["ps", "aux", "--sort=-%cpu,-%mem"]
    stdout, stderr, retcode = run_command(command)

    if retcode != 0:
        return [{
            "user": "HATA", "cpu": "N/A", "mem": "N/A",
            "command": f"İşlemler listelenemedi: {stderr}"
        }]

    processes = []
    lines = stdout.strip().split('\n')
    
    # Başlık satırını atla ve istenen sayıda işlemi al
    for line in lines[1:count + 1]:
        parts = re.split(r'\s+', line, maxsplit=10)
        if len(parts) < 11:
            continue
            
        user = parts[0]
        cpu_usage = parts[2]
        mem_usage = parts[3]
        # Komutun tamamını al
        command_full = parts[10]

        processes.append({
            "user": user,
            "cpu": cpu_usage,
            "mem": mem_usage,
            # Komut çok uzunsa, okunabilirlik için kısalt
            "command": (command_full[:70] + '...') if len(command_full) > 73 else command_full
        })
        
    return processes
