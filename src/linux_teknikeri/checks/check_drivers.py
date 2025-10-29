"""
Donanım sürücü kontrolü ve analiz modülü.
PCI aygıtlarının sürücü durumlarını tespit eder.
"""
import re
import logging
from typing import List, Dict
from ..utils.command_runner import run_command

log = logging.getLogger(__name__)


def get_gpu_driver_info() -> List[Dict[str, str]]:
    """
    Sistemdeki ekran kartlarını ve kullandıkları sürücüleri tespit eder.
    Hatalara karşı güçlendirilmiştir ve lspci çıktısını güvenli bir şekilde ayrıştırır.
    
    Returns:
        List[Dict[str, str]]: Her GPU için {'model': str, 'driver': str} sözlüklerinin listesi.
                              Hata durumunda bile liste döner, içinde hata mesajı bulunur.
    
    Examples:
        >>> gpus = get_gpu_driver_info()
        >>> for gpu in gpus:
        ...     print(f"{gpu['model']} -> {gpu['driver']}")
    """
    try:
        stdout, _, retcode = run_command(["lspci", "-k"])
        if retcode != 0 or not stdout:
            log.error("lspci -k komutu başarısız oldu veya boş çıktı döndürdü.")
            return [{"model": "lspci komutu başarısız oldu", "driver": "Hata"}]

        gpu_info = []
        current_device_block = []

        for line in stdout.strip().split('\n'):
            if not line.strip():
                continue
            
            # Yeni bir aygıt bloğu başlıyor (tab ile başlamayan satırlar)
            if not line.startswith('\t'):
                # Önceki bloğu işle (eğer varsa)
                if current_device_block:
                    block_text = '\n'.join(current_device_block)
                    
                    # Sadece GPU/Ekran kartı bloklarını işle
                    if "VGA compatible controller" in block_text or "3D controller" in block_text:
                        model = current_device_block[0]
                        
                        # Model ismini temizle: "00:02.0 VGA compatible controller: Intel..." -> "Intel..."
                        match = re.search(r'^\S+\s\S+:\s(.+)', model)
                        model = match.group(1).strip() if match else model.strip()
                        
                        # Sürücü bilgisini bul
                        driver_line = next(
                            (l for l in current_device_block if "Kernel driver in use:" in l), 
                            None
                        )
                        driver = driver_line.split(":")[-1].strip() if driver_line else "Sürücü Yüklenmemiş"
                        
                        gpu_info.append({"model": model, "driver": driver})
                
                # Yeni blok başlat
                current_device_block = [line]
            else:
                # Mevcut bloğa satır ekle
                current_device_block.append(line.strip())
        
        # Son bloğu da işle
        if current_device_block:
            block_text = '\n'.join(current_device_block)
            if "VGA compatible controller" in block_text or "3D controller" in block_text:
                model = current_device_block[0]
                match = re.search(r'^\S+\s\S+:\s(.+)', model)
                model = match.group(1).strip() if match else model.strip()
                driver_line = next(
                    (l for l in current_device_block if "Kernel driver in use:" in l), 
                    None
                )
                driver = driver_line.split(":")[-1].strip() if driver_line else "Sürücü Yüklenmemiş"
                gpu_info.append({"model": model, "driver": driver})

        return gpu_info if gpu_info else [{"model": "Uyumlu ekran kartı bulunamadı", "driver": "N/A"}]
    
    except Exception as e:
        log.critical(f"get_gpu_driver_info fonksiyonunda kritik hata: {e}")
        return [{"model": "GPU bilgisi alınırken kritik hata oluştu", "driver": str(e)}]


def get_missing_pci_drivers() -> List[Dict[str, str]]:
    """
    Sistemdeki PCI aygıtlarını tarar ve aktif sürücüsü olmayan (potansiyel sorunlu)
    aygıtları tespit eder.
    
    Özellikle şunları kontrol eder:
    - Ağ kartları (Network controller)
    - Ses kartları (Audio device)
    - USB denetleyiciler (USB controller)
    - Bluetooth adaptörleri
    - Depolama denetleyicileri (Storage controller)
    
    Gereksiz uyarılardan kaçınmak için bazı sistem aygıtları (Bridge, ISA bridge, vb.)
    otomatik olarak filtrelenir.
    
    Returns:
        List[Dict[str, str]]: Sürücüsü eksik aygıtların listesi.
                              Her eleman {'device': str, 'type': str, 'status': str} içerir.
    
    Examples:
        >>> missing = get_missing_pci_drivers()
        >>> if missing:
        ...     for device in missing:
        ...         print(f"⚠️  {device['type']}: {device['device']}")
    """
    try:
        stdout, stderr, retcode = run_command(["lspci", "-k"])
        
        if retcode != 0:
            log.error(f"lspci -k komutu başarısız oldu. Hata: {stderr}")
            return [{"device": "lspci komutu çalıştırılamadı", "type": "HATA", "status": stderr}]

        # Genellikle sürücüye ihtiyaç duymayan veya önemsiz sistem bileşenleri
        # Bu aygıtlar için "sürücü yok" uyarısı göstermek gereksizdir
        ignore_keywords = [
            "Host bridge",          # Ana köprü
            "PCI bridge",           # PCI köprüsü
            "ISA bridge",           # ISA köprüsü
            "RAM memory",           # Bellek kontrolcüsü
            "SRAM",                 # Statik RAM
            "Signal processing",    # Sinyal işleme (genellikle dahili)
            "SMBus",                # Sistem yönetim veri yolu
            "System peripheral",    # Sistem çevre birimleri
        ]
        
        problematic_devices = []
        current_device_block = []
        
        for line in stdout.strip().split('\n'):
            if not line.strip():
                continue
            
            if not line.startswith('\t'):
                # Önceki bloğu analiz et
                if current_device_block:
                    _analyze_device_block(current_device_block, ignore_keywords, problematic_devices)
                
                # Yeni blok başlat
                current_device_block = [line]
            else:
                current_device_block.append(line.strip())
        
        # Son bloğu da analiz et
        if current_device_block:
            _analyze_device_block(current_device_block, ignore_keywords, problematic_devices)
        
        return problematic_devices
    
    except Exception as e:
        log.critical(f"get_missing_pci_drivers fonksiyonunda kritik hata: {e}")
        return [{"device": "Analiz sırasında hata oluştu", "type": "HATA", "status": str(e)}]


def _analyze_device_block(
    block: List[str], 
    ignore_keywords: List[str], 
    result_list: List[Dict[str, str]]
) -> None:
    """
    Bir PCI aygıt bloğunu analiz eder ve sürücü durumunu kontrol eder.
    Bu bir yardımcı (private) fonksiyondur.
    
    Args:
        block: lspci -k çıktısından bir aygıt bloğu (satır listesi)
        ignore_keywords: Göz ardı edilecek aygıt türlerinin anahtar kelimeleri
        result_list: Sorunlu aygıtların ekleneceği liste (mutable, değiştirilir)
    """
    if not block:
        return
    
    device_line = block[0]
    block_text = '\n'.join(block)
    
    # Bu aygıtı göz ardı etmeli miyiz?
    if any(keyword in device_line for keyword in ignore_keywords):
        return
    
    # Sürücü yüklü mü kontrol et
    has_driver = any("Kernel driver in use:" in line for line in block)
    
    # Eğer sürücü yoksa, bu bir sorun olabilir
    if not has_driver:
        # Aygıt tipini belirle (örn: "Network controller", "Audio device")
        device_type_match = re.search(r'^\S+\s+([^:]+):', device_line)
        device_type = device_type_match.group(1).strip() if device_type_match else "Bilinmeyen Aygıt"
        
        # Aygıt modelini belirle
        device_model_match = re.search(r'^\S+\s\S+:\s(.+)', device_line)
        device_model = device_model_match.group(1).strip() if device_model_match else device_line.strip()
        
        # Temizlik: (rev XX) gibi kısımları kaldır
        device_model = re.sub(r'\s*\(rev\s+\w+\)\s*$', '', device_model).strip()
        
        # "Kernel modules:" satırı var mı? (sürücü mevcut ama yüklenmemiş)
        available_modules = None
        for line in block:
            if "Kernel modules:" in line:
                available_modules = line.split(":")[-1].strip()
                break
        
        status = "Sürücü yüklenmemiş"
        if available_modules:
            status = f"Yüklenebilir modüller: {available_modules}"
        
        result_list.append({
            "device": device_model,
            "type": device_type,
            "status": status
        })


def get_driver_recommendations() -> Dict[str, str]:
    """
    Eksik sürücüler için öneriler üretir.
    
    Returns:
        Dict[str, str]: Aygıt tipi -> Öneri eşleştirmesi
    
    Examples:
        >>> recommendations = get_driver_recommendations()
        >>> missing = get_missing_pci_drivers()
        >>> for device in missing:
        ...     advice = recommendations.get(device['type'], "Üretici web sitesini kontrol edin")
        ...     print(f"{device['device']}: {advice}")
    """
    return {
        "Network controller": (
            "Ağ kartı sürücüsü eksik. "
            "Debian/Ubuntu: 'apt search firmware' ile arayın. "
            "Bazı kablosuz kartlar için 'firmware-iwlwifi' veya 'firmware-realtek' gerekebilir."
        ),
        "Ethernet controller": (
            "Ethernet sürücüsü eksik. Genellikle kernel tarafından otomatik yüklenir. "
            "'sudo modprobe <sürücü_adı>' komutunu deneyin."
        ),
        "Audio device": (
            "Ses kartı sürücüsü eksik. "
            "ALSA veya PulseAudio yapılandırmasını kontrol edin. "
            "'alsamixer' komutuyla ses kontrollerini inceleyin."
        ),
        "VGA compatible controller": (
            "Ekran kartı sürücüsü eksik. "
            "Intel: genellikle dahili. NVIDIA: 'nvidia-driver' kurun. AMD: 'amdgpu' kullanın."
        ),
        "USB controller": (
            "USB denetleyici sürücüsü eksik. "
            "Bu genellikle ciddi bir sorundur ve sistem kararsızlığına yol açabilir. "
            "Kernel güncellemesi gerekebilir."
        ),
        "Bluetooth": (
            "Bluetooth sürücüsü eksik. "
            "'bluetooth' ve 'bluez' paketlerinin kurulu olduğundan emin olun. "
            "Firmware gerekebilir: 'apt install firmware-misc-nonfree'"
        ),
    }


def check_proprietary_drivers_available() -> Dict[str, bool]:
    """
    Sistemde özel (proprietary) sürücü yönetim araçlarının mevcut olup olmadığını kontrol eder.
    
    Returns:
        Dict[str, bool]: Araç adı -> Mevcut mu (bool) eşleştirmesi
    
    Examples:
        >>> tools = check_proprietary_drivers_available()
        >>> if tools['ubuntu-drivers']:
        ...     print("Ubuntu Drivers Tool kullanılabilir")
    """
    from ..utils.command_runner import is_command_available
    
    return {
        "ubuntu-drivers": is_command_available("ubuntu-drivers"),  # Ubuntu/Pop!_OS
        "nvidia-detector": is_command_available("nvidia-detector"),  # NVIDIA otomatik tespit
        "nvidia-smi": is_command_available("nvidia-smi"),  # NVIDIA sürücü yüklü mü?
        "amdgpu-install": is_command_available("amdgpu-install"),  # AMD sürücü aracı
    }


def get_nvidia_driver_status() -> Dict[str, str]:
    """
    NVIDIA GPU varsa, sürücü durumunu detaylı kontrol eder.
    
    Returns:
        Dict[str, str]: NVIDIA sürücü durumu bilgileri
    
    Examples:
        >>> status = get_nvidia_driver_status()
        >>> if status['installed']:
        ...     print(f"NVIDIA Sürücü Sürümü: {status['version']}")
    """
    result = {
        "installed": "Hayır",
        "version": "N/A",
        "cuda_version": "N/A",
        "status": "NVIDIA GPU tespit edilemedi veya sürücü yüklü değil"
    }
    
    # nvidia-smi komutu var mı kontrol et
    stdout, stderr, retcode = run_command(["nvidia-smi", "--query-gpu=driver_version", "--format=csv,noheader"], timeout=5)
    
    if retcode == 0 and stdout.strip():
        result["installed"] = "Evet"
        result["version"] = stdout.strip()
        result["status"] = "NVIDIA sürücü aktif ve çalışıyor"
        
        # CUDA sürümünü de al
        cuda_stdout, _, cuda_retcode = run_command(["nvidia-smi", "--query-gpu=cuda_version", "--format=csv,noheader"], timeout=5)
        if cuda_retcode == 0 and cuda_stdout.strip():
            result["cuda_version"] = cuda_stdout.strip()
    else:
        # nouveau (açık kaynak) sürücü kullanılıyor olabilir
        lsmod_stdout, _, lsmod_retcode = run_command(["lsmod"], timeout=5)
        if lsmod_retcode == 0:
            if "nouveau" in lsmod_stdout:
                result["status"] = "Nouveau (açık kaynak) sürücü kullanılıyor"
            elif "nvidia" in lsmod_stdout:
                result["status"] = "NVIDIA sürücü yüklü ama nvidia-smi çalışmıyor"
    
    return result