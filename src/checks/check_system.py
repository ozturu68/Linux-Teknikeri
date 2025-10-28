import platform
import os
import re
from utils.command_runner import run_command

def get_system_info():
    """
    Kategori 1: Sistem Envanteri ve Sürüm Kontrolü
    İşletim sistemi, çekirdek ve kritik yazılım sürümlerini detaylı olarak toplar.
    """
    info = {
        "Kernel Version": platform.release(),
        "Architecture": platform.machine(),
    }

    # 1. İşletim Sistemi ve Dağıtım Bilgileri (hostnamectl kullanarak)
    stdout, _, retcode = run_command(["hostnamectl"])
    if retcode == 0:
        # Regex ile "Operating System" ve "Kernel" satırlarını bulup temizliyoruz
        os_match = re.search(r"Operating System:\s+(.*)", stdout)
        if os_match:
            info["OS Version"] = os_match.group(1).strip()
        
        # Kernel bilgisini platform modülünden aldığımız için bu satırı atlıyoruz.
        # Ancak bu yöntemle de alınabilirdi:
        # kernel_match = re.search(r"Kernel:\s+(.*)", stdout)
        # if kernel_match:
        #     info["Kernel"] = kernel_match.group(1).strip()

    # 2. Masaüstü Ortamı ve Ekran Sunucusu
    desktop_env = os.environ.get("XDG_CURRENT_DESKTOP", "Bilinmiyor")
    display_server = os.environ.get("XDG_SESSION_TYPE", "Bilinmiyor")
    info["Desktop Environment"] = f"{desktop_env} ({display_server.capitalize()})"

    # 3. Kritik Yazılım Sürümleri
    
    # systemd sürümü
    stdout, _, retcode = run_command(["systemctl", "--version"])
    if retcode == 0:
        # İlk satırı al, boşluğa göre böl ve 2. elemanı (sürüm no) al
        systemd_version = stdout.split('\n')[0].split(' ')[1]
        info["Systemd Version"] = systemd_version

    # PipeWire veya PulseAudio sürümü
    stdout, _, retcode = run_command(["pipewire", "--version"])
    if retcode == 0:
        # Çıktı: "pipewire\nCompiled with libpipewire 1.2.1\nLinked with libpipewire 1.2.1" gibi olabilir
        match = re.search(r"libpipewire\s+([\d\.]+)", stdout)
        if match:
            info["Sound Server"] = f"PipeWire {match.group(1)}"
    else:
        # PipeWire yoksa PulseAudio'yu dene
        stdout, _, retcode = run_command(["pulseaudio", "--version"])
        if retcode == 0:
            # Çıktı: "pulseaudio 15.0" gibi
            version = stdout.split(' ')[1]
            info["Sound Server"] = f"PulseAudio {version}"

    # GNOME Shell sürümü (varsa)
    if "GNOME" in desktop_env:
        stdout, _, retcode = run_command(["gnome-shell", "--version"])
        if retcode == 0:
            # Çıktı: "GNOME Shell 42.9"
            info["GNOME Shell Version"] = stdout.strip().replace("GNOME Shell ", "")

    return info
