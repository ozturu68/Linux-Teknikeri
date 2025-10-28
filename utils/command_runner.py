import subprocess

def run_command(command: list[str]) -> tuple[str, str, int]:
    """
    Verilen bir sistem komutunu çalıştırır ve çıktısını, hatasını ve dönüş kodunu döndürür.

    Args:
        command (list[str]): Çalıştırılacak komut ve argümanları bir liste olarak. 
                             Örnek: ["ls", "-l"]

    Returns:
        tuple[str, str, int]: (stdout, stderr, returncode)
                              stdout: Komutun standart çıktısı (başarılı ise).
                              stderr: Komutun hata çıktısı (hata oluşursa).
                              returncode: Komutun dönüş kodu (0 genellikle başarı anlamına gelir).
    """
    try:
        # subprocess.run ile komutu çalıştırıyoruz.
        # capture_output=True: stdout ve stderr'i yakalamamızı sağlar.
        # text=True: Çıktıları metin (string) olarak almamızı sağlar (binary yerine).
        # check=False: Komut hata verirse (returncode != 0) programın çökmesini engeller.
        #              Biz hatayı kendimiz yönetmek istiyoruz.
        result = subprocess.run(
            command, 
            capture_output=True, 
            text=True, 
            check=False
        )
        
        # Yakalanan çıktıları, hataları ve dönüş kodunu bir tuple olarak döndürüyoruz.
        return (result.stdout.strip(), result.stderr.strip(), result.returncode)
    
    except FileNotFoundError:
        # Eğer çalıştırılmak istenen komut sistemde bulunamazsa (örn: "lss" gibi yanlış bir komut)
        # bu hatayı yakalarız.
        error_message = f"Hata: '{command[0]}' komutu sistemde bulunamadı."
        return ("", error_message, -1)
    except Exception as e:
        # Beklenmedik başka bir hata oluşursa, bunu da yakalayıp bildiririz.
        error_message = f"Beklenmedik bir hata oluştu: {e}"
        return ("", error_message, -1)
