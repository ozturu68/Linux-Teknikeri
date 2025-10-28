import re
from utils.command_runner import run_command
import psutil

def get_hardware_info():
    """
    Temel donanım bilgilerini (CPU, GPU, RAM) toplar.
    
    Returns:
        dict: Toplanan donanım bilgilerini içeren bir sözlük.
    """
    info = {}

    # 1. CPU Bilgisini 'inxi' ile al
    # 'inxi -C' komutu sadece CPU bilgilerini verir.
    stdout, _, _ = run_command(["inxi", "-C"])
    # 'model:' ile başlayan satırı bulup, baş kısmı temizliyoruz.
    cpu_model_match = re.search(r"model: (.+?) bits:", stdout)
    if cpu_model_match:
        info["cpu_model"] = cpu_model_match.group(1).strip()

    # 2. GPU Bilgisini 'inxi' ile al
    # 'inxi -G' komutu sadece Grafik kartı bilgilerini verir.
    stdout, _, _ = run_command(["inxi", "-G"])
    # 'Device-1:' veya 'device:' ile başlayan satırı bulup, 'driver:' a kadar olan kısmı alıyoruz.
    gpu_model_match = re.search(r"Device-1: (.+?) driver:", stdout, re.IGNORECASE)
    if gpu_model_match:
        info["gpu_model"] = gpu_model_match.group(1).strip()

    # 3. Bellek (RAM) Bilgisini 'psutil' ile al (komut çalıştırmaktan daha güvenilir)
    # psutil.virtual_memory() sistemdeki bellek bilgilerini bir nesne olarak verir.
    memory = psutil.virtual_memory()
    # Toplam belleği byte cinsinden alır. GB'a çeviriyoruz.
    total_ram_gb = memory.total / (1024 ** 3)
    # Sonucu iki ondalık basamakla formatlıyoruz.
    info["total_ram"] = f"{total_ram_gb:.2f} GB"

    return info
