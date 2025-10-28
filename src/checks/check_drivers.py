import re
from utils.command_runner import run_command

def get_gpu_driver_info():
    """
    Kategori 2: Grafik Sürücü (GPU) Denetimi
    Sistemdeki VGA uyumlu (Ekran Kartı) aygıtları ve kullandıkları çekirdek sürücülerini listeler.
    
    Returns:
        list[dict]: Her biri bir GPU'yu temsil eden ve 'model' ile 'driver' anahtarlarını
                    içeren sözlüklerin bir listesi.
    """
    stdout, stderr, retcode = run_command(["lspci", "-k"])
    
    if retcode != 0:
        print(f"Uyarı: PCI aygıtları listelenemedi. Hata: {stderr}")
        return [{"model": "lspci komutu çalıştırılamadı.", "driver": "Bilinmiyor"}]

    gpu_info = []
    
    # Çıktıyı, her bir aygıt ayrı bir eleman olacak şekilde bölüyoruz.
    device_blocks = re.split(r'\n(?=\S)', stdout.strip())

    for block in device_blocks:
        # Eğer blok bir ekran kartı değilse, atla.
        if "VGA compatible controller" not in block and "3D controller" not in block:
            continue
            
        lines = block.strip().split('\n')
        if not lines:
            continue

        # Model bilgisini ilk satırdan al ve temizle.
        model = lines[0].split(':', 1)[-1].strip()
        
        # Sürücü bilgisini "Kernel driver in use:" satırından bul.
        driver = "Sürücü Yüklenmemiş" # Varsayılan değer
        for line in lines:
            if "Kernel driver in use:" in line:
                driver = line.split(':', 1)[-1].strip()
                break # Sürücüyü bulunca döngüden çık
        
        gpu_info.append({"model": model, "driver": driver})

    return gpu_info


def get_missing_pci_drivers():
    """
    Kategori 2: PCI Aygıt Sürücü Analizi
    `lspci -k` komutunu kullanarak, "Kernel driver in use" satırına sahip olmayan,
    yani aktif bir sürücüsü bulunmayan PCI aygıtlarını tespit eder.
    Gereksiz uyarıları önlemek için yaygın olarak sürücüsüz görünen sistem aygıtlarını filtreler.

    Returns:
        list[str]: Sürücüsü eksik olan ve eylem gerektirebilecek aygıtların listesi.
    """
    stdout, stderr, retcode = run_command(["lspci", "-k"])
    
    if retcode != 0:
        print(f"Uyarı: PCI aygıtları listelenemedi. Hata: {stderr}")
        return ["lspci komutu çalıştırılamadı."]

    problematic_devices = []
    
    ignore_list = [
        "Bridge", "RAM memory", "SRAM", "ISA bridge", "System peripheral",
        "SMBus", "Signal processing controller"
    ]
    
    device_blocks = re.split(r'\n(?=\S)', stdout.strip())

    for block in device_blocks:
        lines = block.strip().split('\n')
        if not lines:
            continue

        device_description = lines[0]
        has_driver = any("Kernel driver in use:" in line for line in lines)
        is_ignorable = any(keyword in device_description for keyword in ignore_list)

        if not has_driver and not is_ignorable:
            clean_description = device_description.split(':', 1)[-1].strip()
            problematic_devices.append(clean_description)

    return problematic_devices