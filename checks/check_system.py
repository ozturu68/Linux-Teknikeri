# Kendi yardımcı fonksiyonumuzu içe aktarıyoruz.
from utils.command_runner import run_command

def get_system_info():
    """
    Sistem envanter bilgilerini (İşletim Sistemi, Çekirdek vb.) toplar.
    
    Returns:
        dict: Toplanan sistem bilgilerini içeren bir sözlük.
    """
    info = {}

    # Çekirdek (Kernel) sürümünü al
    stdout, _, _ = run_command(["uname", "-r"])
    info["kernel_version"] = stdout

    # İşletim sistemi bilgilerini al (lsb_release)
    stdout, _, _ = run_command(["lsb_release", "-ds"])
    # Çıktıdaki tırnak işaretlerini temizliyoruz
    info["os_version"] = stdout.replace('"', '')

    # Sistem mimarisini al
    stdout, _, _ = run_command(["uname", "-m"])
    info["architecture"] = stdout

    return info
