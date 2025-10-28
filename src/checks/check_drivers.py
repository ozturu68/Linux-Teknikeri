import re
from utils.command_runner import run_command

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
    
    # --- YENİ EKLENEN FİLTRE LİSTESİ ---
    # Genellikle sürücü gerektirmeyen veya sürücüsüz görünmesi normal olan
    # aygıtların anahtar kelimelerini içeren liste.
    ignore_list = [
        "Bridge",
        "RAM memory",
        "SRAM",
        "ISA bridge",
        "System peripheral",
        "SMBus",
        "Signal processing controller"
    ]
    
    device_blocks = re.split(r'\n(?=\S)', stdout.strip())

    for block in device_blocks:
        lines = block.strip().split('\n')
        if not lines:
            continue

        device_description = lines[0]
        has_driver = any("Kernel driver in use:" in line for line in lines)
        
        # Eğer sürücü yoksa VE aygıt açıklaması ignore_list'teki hiçbir kelimeyi içermiyorsa
        is_ignorable = any(keyword in device_description for keyword in ignore_list)

        if not has_driver and not is_ignorable:
            clean_description = device_description.split(':', 1)[-1].strip()
            problematic_devices.append(clean_description)

    return problematic_devices