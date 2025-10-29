"""
Linux Teknikeri - Sistem Kontrol Modülleri
==========================================

Sistem, donanım, güvenlik ve performans kontrol fonksiyonları.

Modules:
    - check_system: Sistem bilgileri (OS, kernel, desktop environment)
    - check_hardware: Donanım bilgileri (CPU, GPU, RAM)
    - check_disk: Disk kullanımı ve büyük dosyalar
    - check_storage: S.M.A.R.T. disk sağlığı ve I/O metrikleri
    - check_network: Ağ yapılandırması ve bağlantı bilgileri
    - check_services: Systemd servis analizi
    - check_drivers: GPU ve PCI sürücü kontrolü
    - check_security: Güvenlik denetimi (firewall, SSH, updates)
    - check_performance: CPU/RAM kullanımı ve top processes
    - check_boot: Açılış performans analizi

Author: ozturu68
"""

__all__ = [
    # System
    'get_system_info',
    
    # Hardware
    'get_hardware_info',
    
    # Disk & Storage
    'get_disk_usage',
    'get_top_large_items',
    'check_smart_health',
    'get_disk_io_stats',
    
    # Network
    'get_network_info',
    
    # Services
    'get_running_services',
    'get_failed_services',
    'get_services_with_errors',
    
    # Drivers
    'get_gpu_driver_info',
    'get_missing_pci_drivers',
    'check_loaded_kernel_modules',
    
    # Security
    'get_security_summary',
    'get_listening_ports',
    'audit_ssh_config',
    'check_failed_login_attempts',
    
    # Performance
    'get_top_processes',
    
    # Boot
    'get_boot_blame',
]

# Import tüm check fonksiyonlarını
from .check_system import get_system_info
from .check_hardware import get_hardware_info
from .check_disk import get_disk_usage, get_top_large_items
from .check_storage import check_smart_health, get_disk_io_stats
from .check_network import get_network_info
from .check_services import (
    get_running_services,
    get_failed_services,
    get_services_with_errors
)
from .check_drivers import (
    get_gpu_driver_info,
    get_missing_pci_drivers,
    check_loaded_kernel_modules
)
from .check_security import (
    get_security_summary,
    get_listening_ports,
    audit_ssh_config,
    check_failed_login_attempts
)
from .check_performance import get_top_processes
from .check_boot import get_boot_blame


def get_all_checks():
    """
    Tüm mevcut kontrol fonksiyonlarını döndürür.
    
    Returns:
        dict: Kontrol fonksiyonları sözlüğü
        
    Examples:
        >>> checks = get_all_checks()
        >>> system_info = checks['system']()
    """
    return {
        'system': get_system_info,
        'hardware': get_hardware_info,
        'disk_usage': get_disk_usage,
        'large_items': get_top_large_items,
        'smart_health': check_smart_health,
        'disk_io': get_disk_io_stats,
        'network': get_network_info,
        'running_services': get_running_services,
        'failed_services': get_failed_services,
        'services_with_errors': get_services_with_errors,
        'gpu_drivers': get_gpu_driver_info,
        'missing_pci_drivers': get_missing_pci_drivers,
        'kernel_modules': check_loaded_kernel_modules,
        'security_summary': get_security_summary,
        'listening_ports': get_listening_ports,
        'ssh_audit': audit_ssh_config,
        'failed_logins': check_failed_login_attempts,
        'top_processes': get_top_processes,
        'boot_blame': get_boot_blame,
    }


def run_check_by_name(check_name: str, *args, **kwargs):
    """
    İsme göre kontrol fonksiyonunu çalıştırır.
    
    Args:
        check_name: Kontrol fonksiyonu ismi
        *args: Pozisyonel argümanlar
        **kwargs: Keyword argümanlar
        
    Returns:
        Kontrol sonucu veya None (hata durumunda)
        
    Examples:
        >>> result = run_check_by_name('system')
        >>> gpu_info = run_check_by_name('gpu_drivers')
    """
    checks = get_all_checks()
    
    if check_name not in checks:
        available = ', '.join(checks.keys())
        raise ValueError(
            f"Bilinmeyen kontrol: '{check_name}'. "
            f"Mevcut kontroller: {available}"
        )
    
    try:
        return checks[check_name](*args, **kwargs)
    except Exception as e:
        import logging
        log = logging.getLogger(__name__)
        log.error(f"Kontrol '{check_name}' çalıştırılamadı: {e}")
        return None