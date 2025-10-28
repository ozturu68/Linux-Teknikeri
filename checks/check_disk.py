import psutil

def get_disk_usage():
    """
    Sistemdeki fiziksel disk bölümlerinin kullanım bilgilerini toplar.
    Sanal ve geçici dosya sistemlerini (tmpfs, squashfs vb.) filtreler.
    
    Returns:
        list[dict]: Her biri bir disk bölümünü temsil eden sözlüklerin listesi.
                    Sözlükler hem formatlanmış metin hem de ham analiz verisi içerir.
    """
    partitions_info = []
    valid_fs_types = ['ext4', 'ext3', 'ext2', 'btrfs', 'xfs', 'ntfs', 'fat32', 'vfat']

    all_partitions = psutil.disk_partitions()

    for partition in all_partitions:
        if partition.fstype in valid_fs_types:
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                
                partition_data = {
                    "device": partition.device,
                    "mountpoint": partition.mountpoint,
                    "fstype": partition.fstype,
                    # Raporlama için formatlanmış metin değerleri
                    "total": f"{usage.total / (1024**3):.2f} GB",
                    "used": f"{usage.used / (1024**3):.2f} GB",
                    "free": f"{usage.free / (1024**3):.2f} GB",
                    "percent_used": f"{usage.percent}%",
                    # --- YENİ EKLENEN ALAN ---
                    # Analiz için ham sayısal değer
                    "percent_used_raw": usage.percent
                }
                partitions_info.append(partition_data)
            except PermissionError:
                continue
                
    return partitions_info