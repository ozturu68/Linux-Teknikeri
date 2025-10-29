import re
# --- KRİTİK DÜZELTME ---
# 'utils' modülünün, 'checks' modülünün bir üst dizinindeki ('src')
# bir kardeş klasör olduğunu belirtmek için '..' (iki nokta) ekliyoruz.
from ..utils.command_runner import run_command

def get_hardware_info():
    """Ana donanım bileşenlerini (CPU, GPU, RAM) tespit eder."""
    info = {}

    # CPU Model
    stdout, _, _ = run_command(["lscpu"])
    cpu_model_match = re.search(r"Model name:\s+(.+)", stdout)
    if cpu_model_match:
        info["cpu_model"] = cpu_model_match.group(1).strip()
    else:
        info["cpu_model"] = "Tespit Edilemedi"


    # GPU Model (genellikle birden fazla olabilir, ilkini alalım)
    stdout, _, _ = run_command(["lspci"])
    gpu_model_match = re.search(r"VGA compatible controller: (.+)", stdout)
    if gpu_model_match:
        # Sürücü ve revizyon bilgilerini temizleyelim
        clean_gpu = gpu_model_match.group(1).split('(rev')[0].strip()
        info["gpu_model"] = clean_gpu
    else:
        # İlk GPU bulunamazsa, başka bir arama yapmayı deneyelim (örneğin 3D controller)
        gpu_model_match = re.search(r"3D controller: (.+)", stdout)
        if gpu_model_match:
            clean_gpu = gpu_model_match.group(1).split('(rev')[0].strip()
            info["gpu_model"] = clean_gpu
        else:
            info["gpu_model"] = "Tespit Edilemedi"


    # Total RAM
    stdout, _, _ = run_command(["free", "-h"])
    ram_match = re.search(r"Mem:\s+([\d,.]+\w+)", stdout)
    if ram_match:
        info["total_ram"] = ram_match.group(1)
    else:
        info["total_ram"] = "Tespit Edilemedi"

    return info