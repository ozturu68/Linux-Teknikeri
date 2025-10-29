import psutil
import os
from ..utils.command_runner import run_command

def get_disk_usage():
    """
    Sistemdeki fiziksel disk bölümlerinin kullanım bilgilerini toplar.
    Sanal ve geçici dosya sistemlerini (tmpfs, squashfs vb.) filtreler.
    """
    partitions_info = []
    valid_fs_types = ['ext4', 'ext3', 'ext2', 'btrfs', 'xfs', 'ntfs', 'fat32', 'vfat', 'apfs', 'hfsplus']

    try:
        all_partitions = psutil.disk_partitions()
    except Exception:
        all_partitions = []

    for partition in all_partitions:
        if partition.fstype.lower() in valid_fs_types:
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                partitions_info.append({
                    "device": partition.device,
                    "mountpoint": partition.mountpoint,
                    "fstype": partition.fstype,
                    "total": f"{usage.total / (1024**3):.2f} GB",
                    "used": f"{usage.used / (1024**3):.2f} GB",
                    "free": f"{usage.free / (1024**3):.2f} GB",
                    "percent_used": f"{usage.percent}%",
                    "percent_used_raw": usage.percent
                })
            except (PermissionError, FileNotFoundError):
                continue
                
    return partitions_info

def get_top_large_items(path: str = None, count: int = 10):
    """
    Belirtilen yolda en çok yer kaplayan dosya ve klasörleri bulur.
    Hedef yol belirtilmezse, mevcut kullanıcının ev dizinini kullanır.
    """
    if path is None:
        path = os.path.expanduser('~')

    command = f"du -hd 1 '{path}' | sort -rh | head -n {count + 1}"
    
    # --- ÇÖZÜM BURADA: Zaman aşımı süresini bu yavaş olabilecek komut için 60 saniyeye çıkarıyoruz ---
    stdout, stderr, retcode = run_command(command, use_shell=True, timeout=60)

    if retcode != 0:
        if stderr:
            return [{'size': 'HATA', 'path': stderr.strip()}]
        return []

    large_items = []
    lines = stdout.strip().split('\n')[1:]
    
    for line in lines:
        try:
            size, item_path = line.split('\t', 1)
            large_items.append({
                "size": size.strip(),
                "path": item_path.strip()
            })
        except ValueError:
            continue
            
    return large_items