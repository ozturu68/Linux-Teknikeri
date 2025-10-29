import platform
import os
import logging
from ..utils.command_runner import run_command

log = logging.getLogger(__name__)

def get_system_info():
    """
    Sistemle ilgili temel envanter bilgilerini toplar.
    Hatalara karşı güçlendirilmiştir; bir komut başarısız olduğunda veya
    beklenmedik bir çıktı verdiğinde çökmez, bunun yerine ilgili alan için
    anlamlı bir durum bildirir.
    """
    try:
        info = {
            "kernel_version": "Alınamadı",
            "architecture": "Alınamadı",
            "os_version": "Alınamadı",
            "desktop_environment": "Bilinmiyor",
            "systemd_version": "Alınamadı",
            "sound_server": "Alınamadı",
            "gnome_shell_version": "N/A"
        }

        try:
            info["kernel_version"] = platform.release()
            info["architecture"] = platform.machine()
            info["desktop_environment"] = os.environ.get("XDG_CURRENT_DESKTOP", "Bilinmiyor")
        except Exception as e:
            log.error(f"Platform bilgileri alınırken hata: {e}")

        stdout, _, retcode = run_command(["grep", "^PRETTY_NAME=", "/etc/os-release"])
        if retcode == 0 and stdout:
            try: info["os_version"] = stdout.split("=")[1].strip().strip('"')
            except IndexError: info["os_version"] = "Ayrıştırılamadı"
        
        stdout, _, retcode = run_command(["systemctl", "--version"])
        if retcode == 0 and stdout:
            try: info["systemd_version"] = stdout.split('\n')[0].split(' ')[-1]
            except IndexError: info["systemd_version"] = "Ayrıştırılamadı"

        stdout, _, retcode = run_command(["pactl", "info"])
        if retcode == 0 and stdout:
            if "PipeWire" in stdout: info["sound_server"] = "PipeWire"
            elif "PulseAudio" in stdout: info["sound_server"] = "PulseAudio"
            else: info["sound_server"] = "Tespit Edilemedi"
        
        if "GNOME" in info["desktop_environment"]:
            stdout, _, retcode = run_command(["gnome-shell", "--version"])
            if retcode == 0 and stdout:
                try: info["gnome_shell_version"] = stdout.split(' ')[-1]
                except IndexError: info["gnome_shell_version"] = "Ayrıştırılamadı"
        
        return info

    except Exception as e:
        log.critical(f"get_system_info fonksiyonunda kritik bir hata oluştu: {e}")
        return {"HATA": f"Sistem bilgileri alınırken kritik bir hata oluştu: {e}"}