"""
Linux Teknikeri - Yardımcı Araçlar
==================================

Komut çalıştırma, logging ve diğer yardımcı fonksiyonlar.

Modules:
    - command_runner: Güvenli sistem komutu çalıştırma

Author: ozturu68
"""

__all__ = [
    # Command Runner
    'run_command',
    'run_command_with_retry',
    'run_commands_parallel',
    'safe_command_output',
    'run_command_json',
    'is_command_available',
    'check_required_commands',
    'get_command_stats',
    'reset_command_stats',
    'clear_command_cache',
]

# Command runner imports
from .command_runner import (
    run_command,
    run_command_with_retry,
    run_commands_parallel,
    safe_command_output,
    run_command_json,
    is_command_available,
    check_required_commands,
    get_command_stats,
    reset_command_stats,
    clear_command_cache,
)


# Utility helper fonksiyonları
def format_bytes(size_bytes: float, precision: int = 1) -> str:
    """
    Byte cinsinden boyutu okunabilir formata çevirir.
    
    Args:
        size_bytes: Byte cinsinden boyut
        precision: Ondalık hassasiyeti
        
    Returns:
        str: Okunabilir format (örn: "1.5 GB")
        
    Examples:
        >>> format_bytes(1073741824)
        '1.0 GB'
        >>> format_bytes(1536, precision=2)
        '1.50 KB'
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB', 'PB']:
        if abs(size_bytes) < 1024.0:
            return f"{size_bytes:.{precision}f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.{precision}f} EB"


def format_seconds(seconds: float) -> str:
    """
    Saniye cinsinden süreyi okunabilir formata çevirir.
    
    Args:
        seconds: Saniye cinsinden süre
        
    Returns:
        str: Okunabilir format
        
    Examples:
        >>> format_seconds(90)
        '1m 30s'
        >>> format_seconds(3665)
        '1h 1m 5s'
    """
    if seconds < 60:
        return f"{seconds:.0f}s"
    
    minutes = seconds // 60
    seconds = seconds % 60
    
    if minutes < 60:
        return f"{minutes:.0f}m {seconds:.0f}s"
    
    hours = minutes // 60
    minutes = minutes % 60
    
    if hours < 24:
        return f"{hours:.0f}h {minutes:.0f}m {seconds:.0f}s"
    
    days = hours // 24
    hours = hours % 24
    
    return f"{days:.0f}d {hours:.0f}h {minutes:.0f}m"


def sanitize_filename(filename: str) -> str:
    """
    Dosya adını güvenli hale getirir.
    
    Args:
        filename: Ham dosya adı
        
    Returns:
        str: Güvenli dosya adı
        
    Examples:
        >>> sanitize_filename("my file?.txt")
        'my_file_.txt'
    """
    import re
    # Tehlikeli karakterleri çıkar
    safe = re.sub(r'[^\w\s.-]', '', filename)
    # Boşlukları alt çizgi yap
    safe = safe.replace(' ', '_')
    # Çoklu alt çizgileri tekle
    safe = re.sub(r'_+', '_', safe)
    return safe.strip('_')


def get_timestamp(format: str = "%Y%m%d_%H%M%S") -> str:
    """
    Şu anki zaman damgasını döndürür.
    
    Args:
        format: Zaman formatı (strftime)
        
    Returns:
        str: Zaman damgası
        
    Examples:
        >>> get_timestamp()
        '20251029_114130'
        >>> get_timestamp("%Y-%m-%d")
        '2025-10-29'
    """
    from datetime import datetime
    return datetime.now().strftime(format)


# Package bilgileri
def get_utils_info():
    """
    Utils paketi bilgilerini döndürür.
    
    Returns:
        dict: Paket bilgileri
    """
    return {
        'module': 'linux_teknikeri.utils',
        'functions': __all__,
        'command_stats': get_command_stats()
    }