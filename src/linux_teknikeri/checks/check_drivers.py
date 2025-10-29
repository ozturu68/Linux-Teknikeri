import re
import logging
from ..utils.command_runner import run_command

log = logging.getLogger(__name__)

def get_gpu_driver_info():
    """
    Sistemdeki ekran kartlarını ve kullandıkları sürücüleri tespit eder.
    Hatalara karşı güçlendirilmiştir ve lspci çıktısını güvenli bir şekilde ayrıştırır.
    """
    try:
        stdout, _, retcode = run_command(["lspci", "-k"])
        if retcode != 0 or not stdout:
            log.error("lspci -k komutu başarısız oldu veya boş çıktı döndürdü.")
            return [{"model": "lspci komutu başarısız oldu", "driver": "Hata"}]

        gpu_info = []
        current_device_block = []

        for line in stdout.strip().split('\n'):
            if not line.strip(): continue
            if not line.startswith('\t'):
                if current_device_block:
                    block_text = '\n'.join(current_device_block)
                    if "VGA compatible controller" in block_text or "3D controller" in block_text:
                        model = current_device_block[0]
                        match = re.search(r'^\S+\s\S+:\s(.+)', model)
                        model = match.group(1).strip() if match else model.strip()
                        driver_line = next((l for l in current_device_block if "Kernel driver in use:" in l), None)
                        driver = driver_line.split(":")[-1].strip() if driver_line else "Sürücü Yüklenmemiş"
                        gpu_info.append({"model": model, "driver": driver})
                current_device_block = [line]
            else:
                current_device_block.append(line.strip())
        
        if current_device_block:
            block_text = '\n'.join(current_device_block)
            if "VGA compatible controller" in block_text or "3D controller" in block_text:
                model = current_device_block[0]
                match = re.search(r'^\S+\s\S+:\s(.+)', model)
                model = match.group(1).strip() if match else model.strip()
                driver_line = next((l for l in current_device_block if "Kernel driver in use:" in l), None)
                driver = driver_line.split(":")[-1].strip() if driver_line else "Sürücü Yüklenmemiş"
                gpu_info.append({"model": model, "driver": driver})

        return gpu_info if gpu_info else [{"model": "Uyumlu ekran kartı bulunamadı", "driver": "N/A"}]
    except Exception as e:
        log.critical(f"get_gpu_driver_info fonksiyonunda kritik hata: {e}")
        return [{"model": "GPU bilgisi alınırken kritik hata oluştu", "driver": str(e)}]

# Diğer fonksiyonlar da benzer şekilde zırhlanabilir.
def get_missing_pci_drivers():
    # ... (bu fonksiyonun da zırhlanması gerekir ama şimdilik ana soruna odaklanalım)
    return []