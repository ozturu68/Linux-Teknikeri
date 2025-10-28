import psutil

def get_disk_usage():
    """
    Sistemdeki fiziksel disk bölümlerinin kullanım bilgilerini toplar.
    Sanal ve geçici dosya sistemlerini (tmpfs, squashfs vb.) filtreler.
    
    Returns:
        list[dict]: Her biri bir disk bölümünü temsil eden sözlüklerin listesi.
    """
    partitions_info = []
    # Dikkate alınacak dosya sistemi türleri. Bu, geçici veya sanal sistemleri dışarıda bırakır.
    valid_fs_types = ['ext4', 'ext3', 'ext2', 'btrfs', 'xfs', 'ntfs', 'fat32', 'vfat']

    # Sistemdeki tüm disk bölümlerini alıyoruz.
    all_partitions = psutil.disk_partitions()

    for partition in all_partitions:
        # Sadece belirlediğimiz dosya sistemi türlerindekileri işleme alıyoruz.
        if partition.fstype in valid_fs_types:
            try:
                # Bölümün kullanım bilgilerini alıyoruz.
                usage = psutil.disk_usage(partition.mountpoint)
                
                # Bilgileri daha okunabilir bir sözlük yapısında saklıyoruz.
                partition_data = {
                    "device": partition.device,
                    "mountpoint": partition.mountpoint,
                    "fstype": partition.fstype,
                    # Byte değerlerini GB'a çevirip formatlıyoruz.
                    "total": f"{usage.total / (1024**3):.2f} GB",
                    "used": f"{usage.used / (1024**3):.2f} GB",
                    "free": f"{usage.free / (1024**3):.2f} GB",
                    "percent_used": f"{usage.percent}%"
                }
                partitions_info.append(partition_data)
            except PermissionError:
                # Bazı özel bölümlere erişim hatası alabiliriz, bunları atlıyoruz.
                continue
                
    return partitions_info