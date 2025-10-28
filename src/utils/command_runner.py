import subprocess

def run_command(command: list[str], suppress_stderr: bool = False) -> tuple[str, str, int]:
    """
    Verilen komutu çalıştırır ve çıktıyı, hatayı ve dönüş kodunu döndürür.
    `capture_output` kullanılmadan, stdout ve stderr manuel olarak yönetilir.
    
    Args:
        command (list[str]): Çalıştırılacak komut ve argümanları.
        suppress_stderr (bool, optional): True ise, stderr çıktısı gizlenir. Defaults to False.

    Returns:
        tuple[str, str, int]: stdout, stderr, returncode
    """
    try:
        # stderr'in nereye gideceğini belirle: /dev/null veya bir PIPE.
        stderr_destination = subprocess.DEVNULL if suppress_stderr else subprocess.PIPE

        # capture_output=True kullanmaktan kaçın.
        # stdout ve stderr'i her zaman manuel olarak belirt.
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=stderr_destination,
            text=True,
            check=False 
        )
        
        # stderr gizlenmişse (DEVNULL'a gönderilmişse), result.stderr None olur.
        # Bu durumu kontrol edip her zaman bir string döndürdüğümüzden emin olalım.
        stderr_output = result.stderr if result.stderr is not None else ""
        
        return result.stdout, stderr_output, result.returncode
        
    except FileNotFoundError:
        return "", f"Komut bulunamadı: {command[0]}", 127
    except Exception as e:
        return "", str(e), 1