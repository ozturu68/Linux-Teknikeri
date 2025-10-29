"""
Komut Çalıştırma Yardımcı Modülü
=================================

Sistem komutlarını güvenli, merkezi ve yapılandırılabilir şekilde yönetir.

Features:
    - Güvenli komut çalıştırma (shell injection koruması)
    - Zaman aşımı (timeout) desteği
    - Otomatik retry mekanizması
    - Kapsamlı logging
    - Komut varlık kontrolü
    - Hata yönetimi ve recovery

Author: ozturu68
Version: 0.4.0
Date: 2025-01-29
License: MIT
"""

import subprocess
import shlex
import logging
import time
import os
from typing import Tuple, Union, List, Optional, Dict, Any
from pathlib import Path
from functools import lru_cache

# Logger
log = logging.getLogger(__name__)

# =============================================================================
# SABITLER
# =============================================================================

# Varsayılan zaman aşımı süresi (saniye)
DEFAULT_TIMEOUT = 15

# Maksimum retry sayısı
DEFAULT_MAX_RETRIES = 3

# Retry arasındaki bekleme süresi (saniye)
DEFAULT_RETRY_DELAY = 1.0

# Hassas bilgi içeren komut keyword'leri (loglarda gizlenecek)
SENSITIVE_KEYWORDS = [
    'password', 'passwd', 'pass=', 'pwd=', 'token', 
    'secret', 'api_key', 'apikey', 'auth', 'credential'
]

# Komut çalıştırma istatistikleri
_command_stats: Dict[str, int] = {
    'total': 0,
    'success': 0,
    'failed': 0,
    'timeout': 0,
    'not_found': 0
}


# =============================================================================
# KOMUT VARLIK KONTROLÜ
# =============================================================================

@lru_cache(maxsize=128)
def is_command_available(command: str) -> bool:
    """
    Bir komutun sistemde mevcut olup olmadığını kontrol eder.
    
    LRU cache kullanılarak tekrarlayan kontroller optimize edilir.
    
    Args:
        command: Kontrol edilecek komut adı (örn: "smartctl", "ufw", "git")
        
    Returns:
        bool: Komut mevcutsa True, değilse False
        
    Examples:
        >>> if is_command_available("git"):
        ...     print("Git kurulu")
        >>> if not is_command_available("docker"):
        ...     print("Docker kurulu değil")
        
    Note:
        Bu fonksiyon `which` komutunu kullanır, Linux/Unix sistemlerde standarttır.
    """
    try:
        result = subprocess.run(
            ["which", command],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            text=True,
            check=False
        )
        available = result.returncode == 0
        
        if available:
            log.debug(f"Komut mevcut: {command} -> {result.stdout.strip()}")
        else:
            log.debug(f"Komut bulunamadı: {command}")
            
        return available
        
    except subprocess.TimeoutExpired:
        log.warning(f"Komut kontrolü zaman aşımına uğradı: {command}")
        return False
        
    except FileNotFoundError:
        # 'which' komutu bile yoksa (çok nadir)
        log.error("'which' komutu bulunamadı!")
        return False
        
    except Exception as e:
        log.error(f"Komut kontrolü başarısız ({command}): {e}")
        return False


def check_required_commands(commands: List[str]) -> Tuple[List[str], List[str]]:
    """
    Birden fazla komutun varlığını kontrol eder.
    
    Args:
        commands: Kontrol edilecek komut listesi
        
    Returns:
        Tuple[List[str], List[str]]: (mevcut_komutlar, eksik_komutlar)
        
    Examples:
        >>> available, missing = check_required_commands(['ls', 'grep', 'nonexistent'])
        >>> print(f"Mevcut: {available}, Eksik: {missing}")
        Mevcut: ['ls', 'grep'], Eksik: ['nonexistent']
    """
    available = []
    missing = []
    
    for cmd in commands:
        if is_command_available(cmd):
            available.append(cmd)
        else:
            missing.append(cmd)
    
    return available, missing


# =============================================================================
# GÜVENLİK FONKSİYONLARI
# =============================================================================

def sanitize_log_message(message: str) -> str:
    """
    Log mesajlarından hassas bilgileri temizler.
    
    Args:
        message: Orijinal log mesajı
        
    Returns:
        str: Temizlenmiş mesaj
        
    Examples:
        >>> sanitize_log_message("mysql -u root -pMyPassword123")
        'mysql -u root [HASSAS BİLGİ GİZLENDİ]'
    """
    lower_message = message.lower()
    
    for keyword in SENSITIVE_KEYWORDS:
        if keyword in lower_message:
            # Hassas bilgi bulundu, güvenli versiyonu döndür
            first_word = message.split()[0] if message.split() else message
            return f"{first_word} [HASSAS BİLGİ GİZLENDİ]"
    
    return message


def validate_command_safety(command: Union[str, List[str]]) -> bool:
    """
    Komutun güvenli olup olmadığını temel seviyede kontrol eder.
    
    Args:
        command: Kontrol edilecek komut
        
    Returns:
        bool: Güvenliyse True
        
    Warning:
        Bu basit bir güvenlik kontrolüdür. Shell injection için
        use_shell=False kullanmak daha güvenlidir.
    """
    dangerous_patterns = [
        ';', '&&', '||', '`', '$(',  # Command chaining/injection
        '>', '>>', '<',  # Redirection (use_shell=False ile zaten engellenir)
        '|'  # Pipe (use_shell=False ile engellenir)
    ]
    
    cmd_str = ' '.join(command) if isinstance(command, list) else command
    
    for pattern in dangerous_patterns:
        if pattern in cmd_str:
            log.warning(f"Potansiyel güvenlik riski tespit edildi: {pattern}")
            return False
    
    return True


# =============================================================================
# ANA KOMUT ÇALIŞTIRMA FONKSİYONU
# =============================================================================

def run_command(
    command: Union[str, List[str]], 
    timeout: int = DEFAULT_TIMEOUT, 
    use_shell: bool = False, 
    check: bool = False,
    suppress_stderr: bool = False,
    capture_output: bool = True,
    cwd: Optional[Union[str, Path]] = None,
    env: Optional[Dict[str, str]] = None,
    input_data: Optional[str] = None
) -> Tuple[str, str, int]:
    """
    Verilen bir sistem komutunu çalıştırır ve sonuçlarını döndürür.
    
    Güvenlik Notları:
        - `use_shell=True` kullanırken DİKKATLİ olun! Shell injection riski vardır.
        - Kullanıcı girdilerini asla doğrudan komuta eklemeyin.
        - Mümkünse her zaman `use_shell=False` (varsayılan) kullanın.
        - Hassas bilgiler otomatik olarak loglardan gizlenir.
    
    Args:
        command: Çalıştırılacak komut. Liste veya string olabilir.
                 Liste formatı daha güvenlidir: ["ls", "-la", "/home"]
                 String formatı shell özellikleri gerektiğinde: "ls -la | grep test"
        
        timeout: Komutun maksimum çalışma süresi (saniye). Varsayılan: 15 saniye.
                 Uzun sürecek komutlar için bu değeri artırın.
        
        use_shell: True ise, komut sistem shell'i üzerinden çalıştırılır.
                   Bu, pipe (|), redirect (>) gibi shell özelliklerini kullanmanızı sağlar.
                   GÜVENLİK RİSKİ taşır, dikkatli kullanın!
        
        check: True ise ve komut başarısız olursa CalledProcessError fırlatır.
               Genellikle False bırakılır, hata kontrolü manuel yapılır.
        
        suppress_stderr: True ise, stderr çıktısı bastırılır (gösterilmez).
                         Bazı komutlar gereksiz stderr üretir, bunları gizlemek için.
        
        capture_output: True ise stdout ve stderr yakalanır. False ise terminale yazılır.
        
        cwd: Komutun çalıştırılacağı dizin. None ise mevcut dizin.
        
        env: Ortam değişkenleri. None ise sistem ortamı kullanılır.
        
        input_data: Komuta stdin üzerinden gönderilecek veri.
    
    Returns:
        Tuple[str, str, int]: (stdout, stderr, returncode)
            - stdout: Komutun standart çıktısı (string)
            - stderr: Komutun hata çıktısı (string, suppress_stderr=True ise boş)
            - returncode: Komutun dönüş kodu (0 = başarılı, 0 dışı = hata)
    
    Raises:
        subprocess.TimeoutExpired: Komut timeout süresini aşarsa (döndürülmez, yakalanır)
        subprocess.CalledProcessError: check=True ve komut başarısız olursa
    
    Examples:
        >>> # Basit komut
        >>> stdout, stderr, code = run_command(["ls", "-la"])
        >>> if code == 0:
        ...     print(f"Başarılı: {stdout}")
        
        >>> # Shell özellikleri ile (DİKKATLİ!)
        >>> stdout, stderr, code = run_command("ps aux | grep python", use_shell=True)
        
        >>> # Uzun süren komut
        >>> stdout, stderr, code = run_command(["du", "-sh", "/"], timeout=60)
        
        >>> # Çalışma dizini belirtme
        >>> stdout, stderr, code = run_command(["git", "status"], cwd="/home/user/project")
        
        >>> # Ortam değişkeni ile
        >>> stdout, stderr, code = run_command(
        ...     ["printenv", "MY_VAR"],
        ...     env={"MY_VAR": "test_value"}
        ... )
    """
    global _command_stats
    _command_stats['total'] += 1
    
    try:
        # 1. Komut formatını belirle
        if isinstance(command, str):
            if use_shell:
                cmd = command
            else:
                # String ise ve shell kullanmıyorsak, güvenli parse et
                cmd = shlex.split(command)
                log.debug(f"Komut parse edildi: {cmd}")
        else:
            cmd = command
        
        # 2. Log komutu (hassas bilgileri gizle)
        log_cmd = cmd if isinstance(cmd, str) else ' '.join(cmd)
        safe_log_cmd = sanitize_log_message(log_cmd)
        log.debug(f"Komut çalıştırılıyor: {safe_log_cmd}")
        
        # 3. Güvenlik kontrolü (use_shell=True ise)
        if use_shell and not validate_command_safety(cmd):
            log.warning(f"Güvenlik kontrolü başarısız, yine de çalıştırılıyor: {safe_log_cmd}")
        
        # 4. Subprocess ayarları
        run_kwargs: Dict[str, Any] = {
            "timeout": timeout,
            "shell": use_shell,
            "check": check,
            "text": True,  # Python 3.7+ için (universal_newlines yerine)
        }
        
        # Output yakalama
        if capture_output:
            run_kwargs["stdout"] = subprocess.PIPE
            run_kwargs["stderr"] = subprocess.PIPE if not suppress_stderr else subprocess.DEVNULL
        
        # Çalışma dizini
        if cwd:
            run_kwargs["cwd"] = str(cwd)
            log.debug(f"Çalışma dizini: {cwd}")
        
        # Ortam değişkenleri
        if env:
            # Mevcut ortamı koruyup üzerine ekle
            merged_env = os.environ.copy()
            merged_env.update(env)
            run_kwargs["env"] = merged_env
        
        # Stdin verisi
        if input_data:
            run_kwargs["input"] = input_data
        
        # 5. Komutu çalıştır
        start_time = time.time()
        result = subprocess.run(cmd, **run_kwargs)
        elapsed_time = time.time() - start_time
        
        # 6. Sonuçları al
        stdout = result.stdout if capture_output else ""
        stderr = result.stderr if (capture_output and not suppress_stderr) else ""
        returncode = result.returncode
        
        # 7. Sonucu logla
        if returncode != 0:
            log.warning(
                f"Komut başarısız (kod: {returncode}, süre: {elapsed_time:.2f}s): {safe_log_cmd}"
            )
            if stderr and len(stderr) < 500:
                log.warning(f"Hata mesajı: {stderr.strip()}")
            _command_stats['failed'] += 1
        else:
            log.debug(f"Komut başarılı (süre: {elapsed_time:.2f}s): {safe_log_cmd}")
            _command_stats['success'] += 1
        
        return stdout, stderr, returncode
        
    except subprocess.TimeoutExpired as e:
        _command_stats['timeout'] += 1
        log.error(f"Komut zaman aşımına uğradı ({timeout}s): {safe_log_cmd}")
        return "", f"Komut {timeout} saniye içinde tamamlanamadı", 124
        
    except subprocess.CalledProcessError as e:
        _command_stats['failed'] += 1
        log.error(f"Komut çalıştırılamadı: {safe_log_cmd}, Hata: {e}")
        return e.stdout or "", e.stderr or "", e.returncode
        
    except FileNotFoundError as e:
        _command_stats['not_found'] += 1
        cmd_name = cmd if isinstance(cmd, str) else cmd[0]
        log.error(f"Komut bulunamadı: {cmd_name}")
        return "", f"Komut bulunamadı: {cmd_name}", 127
        
    except PermissionError as e:
        _command_stats['failed'] += 1
        log.error(f"Yetki hatası: {safe_log_cmd}, Hata: {e}")
        return "", f"Yetki hatası: {e}", 126
        
    except Exception as e:
        _command_stats['failed'] += 1
        log.error(f"Beklenmeyen hata: {e}", exc_info=True)
        return "", f"Beklenmeyen hata: {str(e)}", 1


# =============================================================================
# GELİŞMİŞ KOMUT FONKSİYONLARI
# =============================================================================

def run_command_with_retry(
    command: Union[str, List[str]],
    max_attempts: int = DEFAULT_MAX_RETRIES,
    retry_delay: float = DEFAULT_RETRY_DELAY,
    retry_on_codes: Optional[List[int]] = None,
    **kwargs
) -> Tuple[str, str, int]:
    """
    Komutu başarısız olursa belirli kurallara göre tekrar dener.
    
    Args:
        command: Çalıştırılacak komut
        max_attempts: Maksimum deneme sayısı (varsayılan: 3)
        retry_delay: Denemeler arası bekleme süresi (saniye, varsayılan: 1.0)
        retry_on_codes: Hangi hata kodlarında retry yapılacak. 
                        None ise tüm hatalarda retry yapar.
        **kwargs: run_command'a iletilecek diğer parametreler
        
    Returns:
        Tuple[str, str, int]: Son denemenin sonucu
        
    Examples:
        >>> # Ağ bağlantısı gereken bir komut için retry
        >>> stdout, stderr, code = run_command_with_retry(
        ...     ["curl", "example.com"],
        ...     max_attempts=5,
        ...     retry_delay=2.0,
        ...     retry_on_codes=[6, 7, 28]  # curl network error codes
        ... )
        
        >>> # Tüm hatalarda retry
        >>> stdout, stderr, code = run_command_with_retry(
        ...     ["apt", "update"],
        ...     max_attempts=3
        ... )
    """
    for attempt in range(1, max_attempts + 1):
        stdout, stderr, returncode = run_command(command, **kwargs)
        
        # Başarılı
        if returncode == 0:
            if attempt > 1:
                log.info(f"Komut {attempt}. denemede başarılı oldu")
            return stdout, stderr, returncode
        
        # Retry yapılmalı mı kontrol et
        should_retry = True
        if retry_on_codes is not None:
            should_retry = returncode in retry_on_codes
        
        # Son deneme veya retry yapılmamalı
        if attempt >= max_attempts or not should_retry:
            break
        
        # Retry yap
        log.info(
            f"Komut başarısız (kod: {returncode}, deneme: {attempt}/{max_attempts}), "
            f"{retry_delay}s sonra tekrar denenecek..."
        )
        time.sleep(retry_delay)
    
    log.error(f"Komut {max_attempts} denemeden sonra hala başarısız")
    return stdout, stderr, returncode


def run_commands_parallel(
    commands: List[Union[str, List[str]]],
    timeout: int = DEFAULT_TIMEOUT,
    **kwargs
) -> List[Tuple[str, str, int]]:
    """
    Birden fazla komutu paralel olarak çalıştırır.
    
    Args:
        commands: Çalıştırılacak komut listesi
        timeout: Her komut için timeout (saniye)
        **kwargs: run_command'a iletilecek diğer parametreler
        
    Returns:
        List[Tuple[str, str, int]]: Her komut için (stdout, stderr, returncode)
        
    Examples:
        >>> commands = [
        ...     ["uptime"],
        ...     ["free", "-h"],
        ...     ["df", "-h"]
        ... ]
        >>> results = run_commands_parallel(commands)
        >>> for i, (stdout, stderr, code) in enumerate(results):
        ...     print(f"Komut {i+1}: Kod={code}")
    
    Note:
        Bu fonksiyon concurrent.futures kullanır, CPU-bound işler için
        threading yerine multiprocessing tercih edilebilir.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed
    
    results = [None] * len(commands)
    
    with ThreadPoolExecutor(max_workers=min(len(commands), 10)) as executor:
        # Submit all commands
        future_to_index = {
            executor.submit(run_command, cmd, timeout, **kwargs): i
            for i, cmd in enumerate(commands)
        }
        
        # Collect results
        for future in as_completed(future_to_index):
            index = future_to_index[future]
            try:
                results[index] = future.result()
            except Exception as e:
                log.error(f"Paralel komut {index} başarısız: {e}")
                results[index] = ("", str(e), 1)
    
    return results


def safe_command_output(
    command: Union[str, List[str]], 
    default: str = "N/A",
    strip: bool = True,
    **kwargs
) -> str:
    """
    Komutu çalıştırır ve sadece stdout'u döndürür. 
    Hata durumunda default değer döner.
    
    Args:
        command: Çalıştırılacak komut
        default: Hata durumunda döndürülecek değer (varsayılan: "N/A")
        strip: True ise çıktıdaki boşlukları temizler
        **kwargs: run_command'a iletilecek diğer parametreler
        
    Returns:
        str: Komut çıktısı veya default değer
        
    Examples:
        >>> hostname = safe_command_output(["hostname"], default="unknown")
        >>> kernel = safe_command_output("uname -r", default="unknown")
        >>> cpu_model = safe_command_output(
        ...     ["lscpu"],
        ...     default="CPU bilgisi alınamadı"
        ... )
    """
    stdout, stderr, returncode = run_command(command, **kwargs)
    
    if returncode == 0 and stdout:
        return stdout.strip() if strip else stdout
    
    return default


def run_command_json(
    command: Union[str, List[str]],
    **kwargs
) -> Optional[Any]:
    """
    JSON çıktı veren komutu çalıştırır ve parse edilmiş JSON döndürür.
    
    Args:
        command: JSON çıktı veren komut (örn: ["docker", "inspect", "container"])
        **kwargs: run_command'a iletilecek diğer parametreler
        
    Returns:
        Optional[Any]: Parse edilmiş JSON data veya None (hata durumunda)
        
    Examples:
        >>> # Docker container bilgisi
        >>> data = run_command_json(["docker", "inspect", "nginx"])
        >>> if data:
        ...     print(data[0]['State']['Status'])
        
        >>> # Package.json okuma
        >>> pkg = run_command_json(["cat", "package.json"])
        >>> if pkg:
        ...     print(pkg['version'])
    """
    import json
    
    stdout, stderr, returncode = run_command(command, **kwargs)
    
    if returncode != 0:
        log.error(f"Komut başarısız: {stderr}")
        return None
    
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as e:
        log.error(f"JSON parse hatası: {e}")
        return None


# =============================================================================
# İSTATİSTİK VE YARDIMCI FONKSİYONLAR
# =============================================================================

def get_command_stats() -> Dict[str, int]:
    """
    Komut çalıştırma istatistiklerini döndürür.
    
    Returns:
        Dict[str, int]: İstatistik sözlüğü
        
    Examples:
        >>> stats = get_command_stats()
        >>> print(f"Toplam: {stats['total']}, Başarılı: {stats['success']}")
    """
    return _command_stats.copy()


def reset_command_stats() -> None:
    """Komut istatistiklerini sıfırlar."""
    global _command_stats
    for key in _command_stats:
        _command_stats[key] = 0
    log.debug("Komut istatistikleri sıfırlandı")


def clear_command_cache() -> None:
    """is_command_available fonksiyonunun cache'ini temizler."""
    is_command_available.cache_clear()
    log.debug("Komut cache temizlendi")


# =============================================================================
# ÖRNEK KULLANIM (Test Amaçlı)
# =============================================================================

if __name__ == "__main__":
    # Basit test
    logging.basicConfig(level=logging.DEBUG)
    
    print("=== Komut Çalıştırma Modülü Test ===\n")
    
    # Test 1: Basit komut
    print("1. Basit komut (hostname):")
    stdout, stderr, code = run_command(["hostname"])
    print(f"   Sonuç: {stdout.strip()}, Kod: {code}\n")
    
    # Test 2: Komut varlık kontrolü
    print("2. Komut kontrolleri:")
    print(f"   git var mı? {is_command_available('git')}")
    print(f"   docker var mı? {is_command_available('docker')}")
    print(f"   nonexistent var mı? {is_command_available('nonexistent')}\n")
    
    # Test 3: Safe command output
    print("3. Safe output:")
    kernel = safe_command_output("uname -r", default="unknown")
    print(f"   Kernel: {kernel}\n")
    
    # Test 4: İstatistikler
    print("4. İstatistikler:")
    stats = get_command_stats()
    print(f"   {stats}\n")
    
    print("=== Test Tamamlandı ===")