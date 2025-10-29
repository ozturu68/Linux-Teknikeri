"""
Komut çalıştırma yardımcı modülü.
Sistem komutlarını güvenli ve merkezi bir şekilde yönetir.
"""
import subprocess
import shlex
import logging
from typing import Tuple, Union, List

# Logging yapılandırmasını burada yapmıyoruz!
# Ana program (main.py) tarafından yapılandırılacak.
log = logging.getLogger(__name__)

# Varsayılan zaman aşımı süresi (saniye)
DEFAULT_TIMEOUT = 15


def run_command(
    command: Union[str, List[str]], 
    timeout: int = DEFAULT_TIMEOUT, 
    use_shell: bool = False, 
    check: bool = False,
    suppress_stderr: bool = False
) -> Tuple[str, str, int]:
    """
    Verilen bir sistem komutunu çalıştırır ve sonuçlarını döndürür.
    
    Güvenlik Notları:
    - `use_shell=True` kullanırken dikkatli olun! Shell injection riski vardır.
    - Kullanıcı girdilerini asla doğrudan komuta eklemeyin.
    - Mümkünse her zaman `use_shell=False` (varsayılan) kullanın.
    
    Args:
        command: Çalıştırılacak komut. Liste veya string olabilir.
                 Liste formatı daha güvenlidir: ["ls", "-la", "/home"]
                 String formatı shell özellikleri gerektiğinde: "ls -la | grep test"
        
        timeout: Komutun maksimum çalışma süresi (saniye). Varsayılan: 15 saniye.
                 Uzun sürecek komutlar için bu değeri artırın.
        
        use_shell: True ise, komut sistem shell'i üzerinden çalıştırılır.
                   Bu, pipe (|), redirect (>) gibi shell özelliklerini kullanmanızı sağlar.
                   Güvenlik riski taşır, dikkatli kullanın!
        
        check: True ise ve komut başarısız olursa CalledProcessError fırlatır.
               Genellikle False bırakılır, hata kontrolü manuel yapılır.
        
        suppress_stderr: True ise, stderr çıktısı bastırılır (gösterilmez).
                         Bazı komutlar gereksiz stderr üretir, bunları gizlemek için kullanılır.
    
    Returns:
        Tuple[str, str, int]: (stdout, stderr, returncode)
        - stdout: Komutun standart çıktısı (string)
        - stderr: Komutun hata çıktısı (string, suppress_stderr=True ise boş)
        - returncode: Komutun dönüş kodu (0 = başarılı, 0 dışı = hata)
    
    Raises:
        Normalde exception fırlatmaz. Hata durumunda bile (stdout="", stderr="hata mesajı", returncode=hata_kodu)
        formatında tuple döner. Sadece check=True ise CalledProcessError fırlatabilir.
    
    Examples:
        >>> # Liste formatı (güvenli, önerilen)
        >>> stdout, stderr, code = run_command(["ls", "-la"])
        
        >>> # String formatı (shell özellikleri için)
        >>> stdout, stderr, code = run_command("ps aux | grep python", use_shell=True)
        
        >>> # Uzun sürecek komut için timeout artırma
        >>> stdout, stderr, code = run_command(["du", "-sh", "/"], timeout=60)
        
        >>> # Stderr'i bastırma (örn: apt komutları için)
        >>> stdout, stderr, code = run_command(["apt", "list"], suppress_stderr=True)
    """
    
    # --- KOMUT HAZIRLAMA ---
    # Komut tipini ve use_shell parametresini uyumlu hale getir
    if use_shell:
        # Shell kullanılacaksa, komutu string'e çevir
        if isinstance(command, list):
            # Güvenlik: Listeyi basitçe join etmek yerine shlex.join kullan (Python 3.8+)
            try:
                cmd_to_run = shlex.join(command)
            except AttributeError:
                # Python 3.7 ve öncesi için fallback
                cmd_to_run = ' '.join(shlex.quote(arg) for arg in command)
        else:
            cmd_to_run = command
    else:
        # Shell kullanılmayacaksa, komutu listeye çevir
        if isinstance(command, str):
            # shlex.split kullanarak güvenli bir şekilde böl
            cmd_to_run = shlex.split(command)
        else:
            cmd_to_run = command
    
    # Loglama için komutun string gösterimini hazırla
    if isinstance(cmd_to_run, str):
        cmd_str_for_log = cmd_to_run
    else:
        # Liste ise, güvenli bir şekilde string'e çevir
        try:
            cmd_str_for_log = shlex.join(cmd_to_run)
        except AttributeError:
            cmd_str_for_log = ' '.join(shlex.quote(str(arg)) for arg in cmd_to_run)
    
    # Çok uzun komutları kısalt (loglama için)
    if len(cmd_str_for_log) > 100:
        cmd_str_for_log = cmd_str_for_log[:97] + "..."
    
    # --- KOMUT ÇALIŞTIRMA ---
    try:
        log.debug(f"Komut çalıştırılıyor: '{cmd_str_for_log}' (shell={use_shell}, timeout={timeout}s)")
        
        result = subprocess.run(
            cmd_to_run,
            shell=use_shell,
            timeout=timeout,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL if suppress_stderr else subprocess.PIPE,
            text=True,
            encoding='utf-8',
            errors='replace',  # Kodlama hatalarında karakterleri değiştir
            check=check
        )
        
        # Başarılı sonucu logla (sadece debug seviyesinde)
        log.debug(f"Komut tamamlandı. Return code: {result.returncode}")
        
        # stderr bastırılmışsa boş string döndür
        stderr_output = "" if suppress_stderr else (result.stderr or "")
        
        # Komut başarısız olduysa ve stderr bastırılmadıysa uyar
        if result.returncode != 0 and not suppress_stderr and stderr_output:
            log.warning(
                f"Komut başarısız: '{cmd_str_for_log}' "
                f"(kod: {result.returncode}, stderr: '{stderr_output.strip()[:100]}')"
            )
        
        return result.stdout or "", stderr_output, result.returncode
    
    # --- HATA YÖNETİMİ ---
    except FileNotFoundError as e:
        error_msg = f"Komut bulunamadı: '{cmd_str_for_log}'"
        log.error(error_msg)
        return "", error_msg, 127  # 127 = command not found (POSIX standardı)
    
    except subprocess.TimeoutExpired:
        error_msg = f"Komut {timeout} saniye içinde tamamlanamadı: '{cmd_str_for_log}'"
        log.error(error_msg)
        return "", error_msg, 124  # 124 = timeout (GNU timeout komutu standardı)
    
    except subprocess.CalledProcessError as e:
        # check=True kullanıldığında ve komut başarısız olduğunda buraya gelir
        error_msg = f"Komut hata verdi: '{cmd_str_for_log}' (kod: {e.returncode})"
        log.error(error_msg)
        return e.stdout or "", e.stderr or error_msg, e.returncode
    
    except PermissionError as e:
        error_msg = f"Yetki hatası: '{cmd_str_for_log}' - {str(e)}"
        log.error(error_msg)
        return "", error_msg, 126  # 126 = cannot execute (POSIX)
    
    except Exception as e:
        # Beklenmeyen hatalar
        error_msg = f"Beklenmeyen hata: '{cmd_str_for_log}' - {type(e).__name__}: {str(e)}"
        log.critical(error_msg)
        return "", error_msg, 1  # Genel hata kodu


def run_command_with_sudo(
    command: Union[str, List[str]], 
    **kwargs
) -> Tuple[str, str, int]:
    """
    Komutu sudo ile çalıştırır.
    
    Not: sudo şifre sorabilir! Çalıştırmadan önce `sudo -v` ile yetki alındığından emin olun.
    
    Args:
        command: Çalıştırılacak komut
        **kwargs: run_command()'a iletilecek diğer parametreler
    
    Returns:
        Tuple[str, str, int]: (stdout, stderr, returncode)
    
    Example:
        >>> # Önce yetki al
        >>> run_command(["sudo", "-v"])
        >>> # Sonra sudo komutu çalıştır
        >>> stdout, stderr, code = run_command_with_sudo(["smartctl", "-H", "/dev/sda"])
    """
    if isinstance(command, str):
        sudo_command = f"sudo {command}"
    else:
        sudo_command = ["sudo"] + list(command)
    
    return run_command(sudo_command, **kwargs)


def is_command_available(command_name: str) -> bool:
    """
    Belirtilen komutun sistemde mevcut olup olmadığını kontrol eder.
    
    Args:
        command_name: Kontrol edilecek komut adı (örn: "smartctl", "lspci")
    
    Returns:
        bool: Komut mevcutsa True, değilse False
    
    Example:
        >>> if is_command_available("smartctl"):
        ...     print("S.M.A.R.T. kontrolü yapılabilir")
        ... else:
        ...     print("smartmontools paketi kurulu değil")
    """
    stdout, stderr, returncode = run_command(
        ["which", command_name], 
        timeout=5, 
        suppress_stderr=True
    )
    return returncode == 0


def get_command_version(command_name: str, version_arg: str = "--version") -> str:
    """
    Komutun sürüm bilgisini alır.
    
    Args:
        command_name: Komut adı (örn: "python3", "gcc")
        version_arg: Sürüm bilgisi için kullanılacak argüman (genellikle --version)
    
    Returns:
        str: Sürüm bilgisi veya "Bulunamadı" / "Tespit Edilemedi"
    
    Example:
        >>> version = get_command_version("python3")
        >>> print(f"Python sürümü: {version}")
    """
    if not is_command_available(command_name):
        return "Kurulu Değil"
    
    stdout, stderr, returncode = run_command(
        [command_name, version_arg], 
        timeout=5,
        suppress_stderr=True
    )
    
    if returncode == 0 and stdout:
        # İlk satırı al, genellikle sürüm bilgisi ilk satırdadır
        first_line = stdout.strip().split('\n')[0]
        return first_line.strip()
    
    return "Tespit Edilemedi"


# Geriye dönük uyumluluk için eski isimlerle alias'lar
def run_command_simple(command: List[str]) -> Tuple[str, str, int]:
    """
    Eski API için basit komut çalıştırıcı.
    Yeni kodda run_command() kullanın.
    """
    log.warning("run_command_simple() kullanımdan kaldırıldı, run_command() kullanın")
    return run_command(command)