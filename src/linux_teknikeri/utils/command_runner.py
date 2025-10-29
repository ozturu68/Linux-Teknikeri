import subprocess
import shlex
import logging # <-- Hata ayıklama için logging ekliyoruz.

# Bu modül için bir logger oluşturalım.
# Bu, hataları standart bir şekilde kaydetmemizi sağlar.
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
log = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 15

def run_command(command, timeout=DEFAULT_TIMEOUT, use_shell=False, check=False):
    """
    Verilen bir komutu çalıştırır, çıktısını, hatasını ve dönüş kodunu döndürür.
    Hataları loglar ve daha sağlam bir hata yönetimi sunar.

    Args:
        command (str veya list): Çalıştırılacak komut.
        timeout (int): Komutun zaman aşımına uğraması için saniye cinsinden süre.
        use_shell (bool): Kabuk özelliklerini kullanmak için (örn: '|').
        check (bool): Eğer True ise ve komut hata verirse, CalledProcessError fırlatır.
                      Bizim durumumuzda False kalması daha iyi, hataları kendimiz yöneteceğiz.

    Returns:
        tuple: (stdout, stderr, returncode)
        Bir hata durumunda, stdout ve stderr boş string, returncode ise -1 olur.
    """
    if use_shell and isinstance(command, list):
        cmd_to_run = ' '.join(command)
    elif not use_shell and isinstance(command, str):
        cmd_to_run = shlex.split(command)
    else:
        cmd_to_run = command
    
    cmd_str_for_log = cmd_to_run if isinstance(cmd_to_run, str) else ' '.join(cmd_to_run)

    try:
        result = subprocess.run(
            cmd_to_run,
            shell=use_shell,
            timeout=timeout,
            capture_output=True,
            text=True,  # Çıktıyı otomatik olarak string'e çevirir.
            encoding='utf-8',
            errors='replace', # Karakter kodlama hatalarını değiştirir.
            check=check
        )
        
        # Eğer komut başarısız olduysa (retcode != 0), bunu loglayalım.
        if result.returncode != 0:
            log.warning(
                f"Komut '{cmd_str_for_log}' başarısız oldu. "
                f"Return Code: {result.returncode}, Stderr: '{result.stderr.strip()}'"
            )

        return result.stdout, result.stderr, result.returncode

    except FileNotFoundError:
        log.error(f"Komut bulunamadı: '{cmd_str_for_log}'")
        # Hata durumunda tutarlı bir dönüş yapısı sağlıyoruz.
        # stdout ve stderr'in boş string olduğundan emin oluyoruz.
        return "", f"Komut bulunamadı: {cmd_str_for_log}", 127
    
    except subprocess.TimeoutExpired:
        log.error(f"Komut zaman aşımına uğradı ({timeout}s): '{cmd_str_for_log}'")
        return "", f"Zaman aşımı: {cmd_str_for_log}", -1
        
    except Exception as e:
        log.error(f"Komut çalıştırılırken beklenmedik bir hata oluştu: '{cmd_str_for_log}'. Hata: {e}")
        return "", f"Beklenmedik hata: {e}", -1
