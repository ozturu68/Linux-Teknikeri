"""
Donanım Sürücü Kontrolü ve Analiz Modülü
========================================

PCI aygıtlarının sürücü durumlarını tespit eder, GPU sürücülerini analiz eder
ve eksik veya sorunlu sürücüleri raporlar.

Features:
    - GPU sürücü tespiti (NVIDIA, AMD, Intel)
    - Çoklu GPU desteği
    - Eksik PCI sürücü tespiti
    - Sürücü versiyonu kontrolü
    - Vulkan/OpenGL desteği
    - Proprietary vs Open Source sürücü karşılaştırması
    - Kernel modül kontrolü
    - DRM (Direct Rendering Manager) durumu

Author: ozturu68
Version: 0.4.0
Date: 2025-01-29
License: MIT
"""

import re
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from enum import Enum

from ..utils.command_runner import (
    run_command,
    is_command_available,
    safe_command_output
)

# Logger
log = logging.getLogger(__name__)


# =============================================================================
# ENUM VE DATACLASS TANIMLARI
# =============================================================================

class DriverType(Enum):
    """Sürücü tipi enum'ı."""
    PROPRIETARY = "Proprietary"  # Kapalı kaynak (NVIDIA, AMD fglrx)
    OPEN_SOURCE = "Open Source"  # Açık kaynak (nouveau, radeon, amdgpu, intel)
    KERNEL_MODULE = "Kernel Module"  # Çekirdek modülü
    FIRMWARE = "Firmware"  # Firmware
    MISSING = "Yüklenmemiş"
    UNKNOWN = "Bilinmiyor"


class GPUVendor(Enum):
    """GPU üreticisi enum'ı."""
    NVIDIA = "NVIDIA"
    AMD = "AMD"
    INTEL = "Intel"
    OTHER = "Diğer"


@dataclass
class GPUInfo:
    """GPU bilgi sınıfı."""
    model: str
    vendor: str
    driver: str
    driver_type: str
    driver_version: Optional[str] = None
    kernel_module: Optional[str] = None
    pci_id: Optional[str] = None
    bus_id: Optional[str] = None
    vram: Optional[str] = None
    opengl_version: Optional[str] = None
    vulkan_support: Optional[bool] = None
    cuda_version: Optional[str] = None  # NVIDIA için
    recommendations: List[str] = None
    warnings: List[str] = None
    
    def __post_init__(self):
        if self.recommendations is None:
            self.recommendations = []
        if self.warnings is None:
            self.warnings = []
    
    def to_dict(self) -> Dict[str, Any]:
        """Dataclass'ı dictionary'e çevirir."""
        return asdict(self)


@dataclass
class PCIDevice:
    """PCI cihaz bilgi sınıfı."""
    bus_id: str
    device_class: str
    vendor: str
    device_name: str
    driver: Optional[str] = None
    kernel_module: Optional[str] = None
    has_driver: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Dataclass'ı dictionary'e çevirir."""
        return asdict(self)


# =============================================================================
# GPU SÜRÜCÜ TESPİTİ VE ANALİZİ
# =============================================================================

def get_gpu_driver_info() -> List[Dict[str, Any]]:
    """
    Sistemdeki ekran kartlarını ve kullandıkları sürücüleri tespit eder.
    Çoklu GPU sistemlerini destekler ve detaylı analiz yapar.
    
    Returns:
        List[Dict[str, Any]]: Her GPU için detaylı bilgi sözlükleri
    
    Examples:
        >>> gpus = get_gpu_driver_info()
        >>> for gpu in gpus:
        ...     print(f"{gpu['model']} -> {gpu['driver']}")
        ...     if gpu['warnings']:
        ...         for warning in gpu['warnings']:
        ...             print(f"  ⚠️  {warning}")
    
    Note:
        - lspci komutu gereklidir
        - Bazı bilgiler için sudo yetkisi gerekebilir
        - NVIDIA/AMD proprietary sürücüler için ek komutlar kullanılır
    """
    try:
        stdout, stderr, retcode = run_command(["lspci", "-k"], timeout=10)
        
        if retcode != 0 or not stdout:
            log.error("lspci komutu başarısız oldu")
            return [{"model": "lspci komutu başarısız", "driver": "Hata"}]
        
        gpus = _parse_lspci_output(stdout)
        
        # Her GPU için detaylı analiz
        for gpu in gpus:
            _enrich_gpu_info(gpu)
            _analyze_gpu_driver(gpu)
        
        return [gpu.to_dict() for gpu in gpus]
        
    except Exception as e:
        log.error(f"GPU sürücü bilgisi alınamadı: {e}", exc_info=True)
        return [{"model": f"Hata: {str(e)}", "driver": "Hata"}]


def _parse_lspci_output(lspci_output: str) -> List[GPUInfo]:
    """
    lspci -k çıktısını parse eder ve GPU listesi döndürür.
    
    Args:
        lspci_output: lspci -k komutunun çıktısı
        
    Returns:
        List[GPUInfo]: GPU bilgi listesi
    """
    gpus = []
    current_device_block = []
    
    for line in lspci_output.strip().split('\n'):
        if not line.strip():
            continue
        
        # Yeni bir aygıt bloğu başlıyor (tab ile başlamayan satırlar)
        if not line.startswith('\t'):
            # Önceki bloğu işle (eğer GPU ise)
            if current_device_block:
                gpu = _process_device_block(current_device_block)
                if gpu:
                    gpus.append(gpu)
            
            # Yeni blok başlat
            current_device_block = [line]
        else:
            # Mevcut bloğa satır ekle
            current_device_block.append(line.strip())
    
    # Son bloğu da işle
    if current_device_block:
        gpu = _process_device_block(current_device_block)
        if gpu:
            gpus.append(gpu)
    
    return gpus


def _process_device_block(device_block: List[str]) -> Optional[GPUInfo]:
    """
    Tek bir PCI cihaz bloğunu işler ve GPU ise GPUInfo döndürür.
    
    Args:
        device_block: lspci çıktısından bir cihaz bloğu
        
    Returns:
        Optional[GPUInfo]: GPU bilgisi veya None
    """
    block_text = '\n'.join(device_block)
    
    # Sadece GPU/Ekran kartı bloklarını işle
    if not any(keyword in block_text for keyword in [
        'VGA compatible controller',
        '3D controller',
        'Display controller'
    ]):
        return None
    
    # İlk satırdan bus ID, model ve vendor bilgisini al
    first_line = device_block[0]
    
    # Format: "00:02.0 VGA compatible controller: Intel Corporation ..."
    bus_id_match = re.match(r'^(\S+)\s+(.+?):\s+(.+)', first_line)
    if not bus_id_match:
        return None
    
    bus_id = bus_id_match.group(1)
    device_type = bus_id_match.group(2)
    full_name = bus_id_match.group(3)
    
    # Model ismini temizle
    model = _clean_gpu_model_name(full_name)
    
    # Vendor'u belirle
    vendor = _detect_gpu_vendor(full_name)
    
    # Sürücü bilgisini bul
    driver = None
    kernel_module = None
    
    for line in device_block[1:]:
        if "Kernel driver in use:" in line:
            driver = line.split(":")[-1].strip()
        elif "Kernel modules:" in line:
            # Birden fazla modül olabilir
            modules = line.split(":")[-1].strip()
            kernel_module = modules.split(',')[0].strip()  # İlkini al
    
    if not driver:
        driver = "Sürücü Yüklenmemiş"
    
    # GPU bilgilerini oluştur
    gpu = GPUInfo(
        model=model,
        vendor=vendor,
        driver=driver,
        driver_type=_determine_driver_type(driver, vendor),
        kernel_module=kernel_module,
        bus_id=bus_id
    )
    
    return gpu


def _clean_gpu_model_name(full_name: str) -> str:
    """
    GPU model ismini temizler.
    
    Args:
        full_name: Ham GPU model adı
        
    Returns:
        str: Temizlenmiş model adı
    """
    # Revizyon bilgilerini kaldır: (rev 01), (rev a1), vb.
    clean = re.sub(r'\s*\(rev\s+[^\)]+\)', '', full_name)
    
    # Subsystem bilgilerini kaldır: [subsys ...]
    clean = re.sub(r'\s*\[[^\]]*subsys[^\]]*\]', '', clean, flags=re.IGNORECASE)
    
    # Köşeli parantez içindeki diğer bilgileri kaldır
    clean = re.sub(r'\s*\[[^\]]+\]', '', clean)
    
    # Fazla boşlukları temizle
    clean = ' '.join(clean.split())
    
    return clean.strip()


def _detect_gpu_vendor(model_name: str) -> str:
    """
    GPU vendor'unu model adından tespit eder.
    
    Args:
        model_name: GPU model adı
        
    Returns:
        str: Vendor adı
    """
    model_lower = model_name.lower()
    
    if 'nvidia' in model_lower or 'geforce' in model_lower or 'quadro' in model_lower:
        return GPUVendor.NVIDIA.value
    elif 'amd' in model_lower or 'radeon' in model_lower or 'ati' in model_lower:
        return GPUVendor.AMD.value
    elif 'intel' in model_lower:
        return GPUVendor.INTEL.value
    else:
        return GPUVendor.OTHER.value


def _determine_driver_type(driver: str, vendor: str) -> str:
    """
    Sürücü tipini belirler (Proprietary/Open Source/vb.).
    
    Args:
        driver: Sürücü adı
        vendor: GPU vendor'u
        
    Returns:
        str: Sürücü tipi
    """
    driver_lower = driver.lower()
    
    # NVIDIA
    if 'nvidia' in driver_lower and 'nouveau' not in driver_lower:
        return DriverType.PROPRIETARY.value
    elif 'nouveau' in driver_lower:
        return DriverType.OPEN_SOURCE.value
    
    # AMD
    elif 'amdgpu' in driver_lower:
        return DriverType.OPEN_SOURCE.value
    elif 'fglrx' in driver_lower:
        return DriverType.PROPRIETARY.value
    elif 'radeon' in driver_lower:
        return DriverType.OPEN_SOURCE.value
    
    # Intel
    elif 'i915' in driver_lower or 'intel' in driver_lower:
        return DriverType.OPEN_SOURCE.value
    
    # Diğer
    elif driver == "Sürücü Yüklenmemiş":
        return DriverType.MISSING.value
    else:
        return DriverType.UNKNOWN.value


def _enrich_gpu_info(gpu: GPUInfo) -> None:
    """
    GPU bilgilerini ek komutlarla zenginleştirir.
    
    Args:
        gpu: GPUInfo nesnesi (in-place güncellenir)
    """
    # NVIDIA için özel bilgiler
    if gpu.vendor == GPUVendor.NVIDIA.value and gpu.driver_type == DriverType.PROPRIETARY.value:
        _get_nvidia_info(gpu)
    
    # AMD için özel bilgiler
    elif gpu.vendor == GPUVendor.AMD.value:
        _get_amd_info(gpu)
    
    # Intel için özel bilgiler
    elif gpu.vendor == GPUVendor.INTEL.value:
        _get_intel_info(gpu)
    
    # OpenGL/Vulkan kontrolü (tüm GPU'lar için)
    _check_graphics_api_support(gpu)


def _get_nvidia_info(gpu: GPUInfo) -> None:
    """
    NVIDIA GPU için ek bilgiler toplar.
    
    Args:
        gpu: GPUInfo nesnesi
    """
    # nvidia-smi komutu ile detaylı bilgi al
    if is_command_available("nvidia-smi"):
        stdout, stderr, retcode = run_command(
            ["nvidia-smi", "--query-gpu=driver_version,memory.total,compute_cap", "--format=csv,noheader"],
            timeout=5
        )
        
        if retcode == 0 and stdout:
            parts = stdout.strip().split(',')
            if len(parts) >= 1:
                gpu.driver_version = parts[0].strip()
            if len(parts) >= 2:
                gpu.vram = parts[1].strip()
            if len(parts) >= 3:
                gpu.cuda_version = f"Compute Capability {parts[2].strip()}"
    
    # CUDA version
    if is_command_available("nvcc"):
        version = safe_command_output(["nvcc", "--version"], default="")
        if version:
            cuda_match = re.search(r'release\s+([\d.]+)', version)
            if cuda_match:
                gpu.cuda_version = f"CUDA {cuda_match.group(1)}"


def _get_amd_info(gpu: GPUInfo) -> None:
    """
    AMD GPU için ek bilgiler toplar.
    
    Args:
        gpu: GPUInfo nesnesi
    """
    # ROCm info (AMD'nin CUDA benzeri platformu)
    if is_command_available("rocm-smi"):
        stdout, stderr, retcode = run_command(["rocm-smi", "--showdriverversion"], timeout=5)
        if retcode == 0 and stdout:
            version_match = re.search(r'Driver version:\s*(.+)', stdout)
            if version_match:
                gpu.driver_version = version_match.group(1).strip()


def _get_intel_info(gpu: GPUInfo) -> None:
    """
    Intel GPU için ek bilgiler toplar.
    
    Args:
        gpu: GPUInfo nesnesi
    """
    # Intel GPU tools
    if is_command_available("intel_gpu_top"):
        # Intel GPU var
        gpu.driver_version = "Kernel içinde (i915)"


def _check_graphics_api_support(gpu: GPUInfo) -> None:
    """
    OpenGL ve Vulkan desteğini kontrol eder.
    
    Args:
        gpu: GPUInfo nesnesi
    """
    # OpenGL kontrolü
    if is_command_available("glxinfo"):
        stdout, stderr, retcode = run_command(
            ["glxinfo"],
            timeout=5,
            suppress_stderr=True
        )
        
        if retcode == 0 and stdout:
            # OpenGL version
            gl_version_match = re.search(r'OpenGL version string:\s*(.+)', stdout)
            if gl_version_match:
                gpu.opengl_version = gl_version_match.group(1).strip()
    
    # Vulkan kontrolü
    if is_command_available("vulkaninfo"):
        stdout, stderr, retcode = run_command(
            ["vulkaninfo", "--summary"],
            timeout=5,
            suppress_stderr=True
        )
        
        gpu.vulkan_support = (retcode == 0 and "Vulkan Instance Version" in stdout)


def _analyze_gpu_driver(gpu: GPUInfo) -> None:
    """
    GPU sürücüsünü analiz eder ve öneriler/uyarılar üretir.
    
    Args:
        gpu: GPUInfo nesnesi
    """
    # NVIDIA analizi
    if gpu.vendor == GPUVendor.NVIDIA.value:
        if gpu.driver == "nouveau":
            gpu.warnings.append(
                "Açık kaynak 'nouveau' sürücüsü kullanılıyor. "
                "Performans düşük olabilir."
            )
            gpu.recommendations.append(
                "🚀 NVIDIA proprietary sürücüsü kurulumu önerilir: "
                "sudo apt install nvidia-driver-XXX"
            )
        elif gpu.driver == "Sürücü Yüklenmemiş":
            gpu.warnings.append("NVIDIA GPU için sürücü yüklenmemiş!")
            gpu.recommendations.append(
                "Sürücü kurun: sudo ubuntu-drivers autoinstall"
            )
        elif "nvidia" in gpu.driver.lower():
            gpu.recommendations.append(
                "✅ NVIDIA proprietary sürücü aktif (iyi performans)"
            )
    
    # AMD analizi
    elif gpu.vendor == GPUVendor.AMD.value:
        if gpu.driver == "radeon":
            gpu.warnings.append(
                "Eski 'radeon' sürücüsü kullanılıyor. "
                "Yeni kartlar için 'amdgpu' önerilir."
            )
        elif gpu.driver == "amdgpu":
            gpu.recommendations.append(
                "✅ Modern AMDGPU sürücü aktif"
            )
        elif gpu.driver == "Sürücü Yüklenmemiş":
            gpu.warnings.append("AMD GPU için sürücü yüklenmemiş!")
    
    # Intel analizi
    elif gpu.vendor == GPUVendor.INTEL.value:
        if gpu.driver in ["i915", "intel"]:
            gpu.recommendations.append(
                "✅ Intel GPU sürücüsü kernel içinde aktif"
            )
        elif gpu.driver == "Sürücü Yüklenmemiş":
            gpu.warnings.append(
                "Intel GPU için sürücü yüklenmemiş (nadir durum)"
            )
    
    # OpenGL/Vulkan uyarıları
    if gpu.opengl_version is None:
        gpu.warnings.append(
            "OpenGL desteği tespit edilemedi. "
            "3D uygulamalar çalışmayabilir."
        )
    
    if gpu.vulkan_support is False:
        gpu.recommendations.append(
            "💡 Vulkan desteği yok. Modern oyunlar için: "
            "sudo apt install vulkan-tools"
        )


# =============================================================================
# EKSİK PCI SÜRÜCÜ TESPİTİ
# =============================================================================

def get_missing_pci_drivers() -> List[Dict[str, Any]]:
    """
    Sürücüsü eksik PCI aygıtlarını tespit eder.
    
    Returns:
        List[Dict[str, Any]]: Sürücüsü eksik aygıt listesi
    
    Examples:
        >>> missing = get_missing_pci_drivers()
        >>> for device in missing:
        ...     print(f"⚠️  {device['device_name']} - Sürücü yok!")
    
    Note:
        Bazı cihazlar (örn: ISA bridge) sürücü gerektirmez, bunlar filtrelenir.
    """
    try:
        stdout, stderr, retcode = run_command(["lspci", "-k"], timeout=10)
        
        if retcode != 0 or not stdout:
            log.error("lspci komutu başarısız")
            return []
        
        devices = _parse_all_pci_devices(stdout)
        
        # Sürücüsü eksik olanları filtrele
        missing = [
            device for device in devices
            if not device.has_driver and _requires_driver(device)
        ]
        
        return [device.to_dict() for device in missing]
        
    except Exception as e:
        log.error(f"PCI aygıt analizi başarısız: {e}")
        return []


def _parse_all_pci_devices(lspci_output: str) -> List[PCIDevice]:
    """
    Tüm PCI cihazlarını parse eder.
    
    Args:
        lspci_output: lspci -k çıktısı
        
    Returns:
        List[PCIDevice]: PCI cihaz listesi
    """
    devices = []
    current_device_block = []
    
    for line in lspci_output.strip().split('\n'):
        if not line.strip():
            continue
        
        if not line.startswith('\t'):
            # Önceki bloğu işle
            if current_device_block:
                device = _parse_pci_device_block(current_device_block)
                if device:
                    devices.append(device)
            
            current_device_block = [line]
        else:
            current_device_block.append(line.strip())
    
    # Son bloğu işle
    if current_device_block:
        device = _parse_pci_device_block(current_device_block)
        if device:
            devices.append(device)
    
    return devices


def _parse_pci_device_block(block: List[str]) -> Optional[PCIDevice]:
    """
    Tek bir PCI cihaz bloğunu parse eder.
    
    Args:
        block: Cihaz satırları
        
    Returns:
        Optional[PCIDevice]: PCI cihaz bilgisi
    """
    first_line = block[0]
    
    # Format: "00:00.0 Host bridge: Intel Corporation ..."
    match = re.match(r'^(\S+)\s+(.+?):\s+(.+)', first_line)
    if not match:
        return None
    
    bus_id = match.group(1)
    device_class = match.group(2)
    full_name = match.group(3)
    
    # Vendor ve device name'i ayır
    if ':' in full_name:
        vendor, device_name = full_name.split(':', 1)
        vendor = vendor.strip()
        device_name = device_name.strip()
    else:
        vendor = "Unknown"
        device_name = full_name
    
    # Sürücü bilgisi
    driver = None
    kernel_module = None
    
    for line in block[1:]:
        if "Kernel driver in use:" in line:
            driver = line.split(":")[-1].strip()
        elif "Kernel modules:" in line:
            modules = line.split(":")[-1].strip()
            kernel_module = modules.split(',')[0].strip()
    
    device = PCIDevice(
        bus_id=bus_id,
        device_class=device_class,
        vendor=vendor,
        device_name=device_name,
        driver=driver,
        kernel_module=kernel_module,
        has_driver=(driver is not None)
    )
    
    return device


def _requires_driver(device: PCIDevice) -> bool:
    """
    Bir cihazın sürücü gerektirip gerektirmediğini kontrol eder.
    
    Args:
        device: PCI cihaz
        
    Returns:
        bool: Sürücü gerekiyorsa True
    """
    # Bazı cihaz türleri sürücü gerektirmez
    no_driver_classes = [
        'Host bridge',
        'ISA bridge',
        'PCI bridge',
        'SMBus',
        'Signal processing controller',
        'RAM memory',
        'Non-VGA unclassified device'
    ]
    
    for cls in no_driver_classes:
        if cls in device.device_class:
            return False
    
    return True


# =============================================================================
# KERNEL MODÜL KONTROLÜ
# =============================================================================

def check_loaded_kernel_modules() -> Dict[str, Any]:
    """
    Yüklü kernel modüllerini kontrol eder.
    
    Returns:
        Dict[str, Any]: Modül bilgileri
    """
    stdout, stderr, retcode = run_command(["lsmod"], timeout=5)
    
    if retcode != 0:
        return {"error": "lsmod komutu başarısız"}
    
    # GPU ile ilgili modülleri ara
    gpu_modules = []
    for line in stdout.split('\n')[1:]:  # İlk satır başlık
        if not line.strip():
            continue
        
        parts = line.split()
        if len(parts) < 1:
            continue
        
        module_name = parts[0]
        
        # GPU ile ilgili modüller
        gpu_keywords = ['nvidia', 'nouveau', 'amdgpu', 'radeon', 'i915', 'intel']
        if any(keyword in module_name.lower() for keyword in gpu_keywords):
            gpu_modules.append(module_name)
    
    return {
        "gpu_modules": gpu_modules,
        "total_modules": len(stdout.split('\n')) - 1
    }


# =============================================================================
# ÖRNEK KULLANIM
# =============================================================================

if __name__ == "__main__":
    # Test
    import json
    
    logging.basicConfig(level=logging.DEBUG)
    
    print("=== Sürücü Analizi Test ===\n")
    
    # 1. GPU sürücüleri
    print("1. GPU Sürücü Bilgileri:")
    gpus = get_gpu_driver_info()
    print(json.dumps(gpus, indent=2, ensure_ascii=False))
    
    # 2. Eksik PCI sürücüler
    print("\n2. Eksik PCI Sürücüler:")
    missing = get_missing_pci_drivers()
    print(json.dumps(missing, indent=2, ensure_ascii=False))
    
    # 3. Yüklü kernel modüller
    print("\n3. GPU Kernel Modülleri:")
    modules = check_loaded_kernel_modules()
    print(json.dumps(modules, indent=2, ensure_ascii=False))
    
    print("\n=== Test Tamamlandı ===")