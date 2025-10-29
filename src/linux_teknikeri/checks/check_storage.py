"""
Disk ve depolama sağlığı analiz modülü.
S.M.A.R.T. durumu, disk ömrü, sıcaklık ve performans metrikleri kontrolü.
"""
import re
import logging
from typing import Dict, List, Optional, Tuple
from ..utils.command_runner import run_command, is_command_available

log = logging.getLogger(__name__)


def check_smart_health() -> Dict[str, any]:
    """
    Tüm fiziksel disklerin S.M.A.R.T. sağlık durumunu kontrol eder.
    
    S.M.A.R.T. (Self-Monitoring, Analysis and Reporting Technology):
    - Disk arızalarını öngörmeye yardımcı olur
    - Önemli parametreleri izler (hata oranları, sıcaklık, vb.)
    - Disk ömrü hakkında bilgi verir
    
    Returns:
        Dict: {
            'status': str,  # İYİ, SORUNLU, KONTROL EDİLEMEDİ, BİLGİ YOK
            'failing_disks': List[str],  # Sorunlu disklerin listesi
            'disk_details': List[Dict]  # Her disk için detaylı bilgi
        }
    
    Examples:
        >>> health = check_smart_health()
        >>> if health['status'] == 'SORUNLU':
        ...     for disk in health['failing_disks']:
        ...         print(f"⚠️  {disk}")
    """
    # smartctl komutunun varlığını kontrol et
    if not is_command_available("smartctl"):
        return {
            "status": "KONTROL EDİLEMEDİ",
            "failing_disks": [
                "'smartmontools' paketi kurulu değil.",
                "Kurulum: sudo apt install smartmontools"
            ],
            "disk_details": []
        }
    
    # Fiziksel diskleri listele
    stdout, stderr, retcode = run_command(["lsblk", "-dno", "NAME,TYPE"], timeout=10)
    
    if retcode != 0:
        return {
            "status": "KONTROL EDİLEMEDİ",
            "failing_disks": [f"Diskler listelenemedi: {stderr.strip()}"],
            "disk_details": []
        }
    
    # Fiziksel diskleri filtrele (loop, zram, vb. sanal diskleri atla)
    disk_names = [
        line.split()[0] 
        for line in stdout.strip().split('\n')
        if 'disk' in line and not any(x in line for x in ['loop', 'zram', 'ram'])
    ]
    
    if not disk_names:
        return {
            "status": "BİLGİ YOK",
            "failing_disks": ["S.M.A.R.T. kontrol edilebilecek fiziksel disk bulunamadı."],
            "disk_details": []
        }
    
    failing_disks = []
    disk_details = []
    all_ok = True
    
    for disk in disk_names:
        device_path = f"/dev/{disk}"
        disk_info = _analyze_disk_smart(device_path)
        disk_details.append(disk_info)
        
        if disk_info['health_status'] not in ['PASSED', 'OK']:
            all_ok = False
            failing_disks.append(f"{device_path}: {disk_info['health_status']}")
    
    if not all_ok:
        return {
            "status": "SORUNLU",
            "failing_disks": failing_disks,
            "disk_details": disk_details
        }
    
    return {
        "status": "İYİ",
        "failing_disks": [],
        "disk_details": disk_details
    }


def _analyze_disk_smart(device_path: str) -> Dict[str, any]:
    """
    Tek bir diskin S.M.A.R.T. verilerini detaylı olarak analiz eder.
    
    Args:
        device_path: Disk yolu (örn: /dev/sda)
    
    Returns:
        Dict: Disk sağlık bilgileri
    """
    disk_info = {
        'device': device_path,
        'health_status': 'UNKNOWN',
        'temperature': 'N/A',
        'power_on_hours': 'N/A',
        'power_cycle_count': 'N/A',
        'reallocated_sectors': 'N/A',
        'wear_leveling': 'N/A',  # SSD için
        'model': 'N/A',
        'serial': 'N/A',
        'capacity': 'N/A',
        'smart_support': False,
        'warnings': []
    }
    
    # Önce genel bilgileri al (-i parametresi)
    stdout_info, stderr_info, retcode_info = run_command(
        ["sudo", "smartctl", "-i", device_path],
        timeout=10
    )
    
    if retcode_info == 0 and stdout_info:
        # Model
        model_match = re.search(r'Device Model:\s+(.+)', stdout_info)
        if model_match:
            disk_info['model'] = model_match.group(1).strip()
        else:
            # NVMe diskler için alternatif
            model_match = re.search(r'Model Number:\s+(.+)', stdout_info)
            if model_match:
                disk_info['model'] = model_match.group(1).strip()
        
        # Seri numarası
        serial_match = re.search(r'Serial [Nn]umber:\s+(.+)', stdout_info)
        if serial_match:
            disk_info['serial'] = serial_match.group(1).strip()
        
        # Kapasite
        capacity_match = re.search(r'User Capacity:\s+[\d,]+ bytes \[(.+?)\]', stdout_info)
        if capacity_match:
            disk_info['capacity'] = capacity_match.group(1).strip()
        
        # S.M.A.R.T. desteği
        if 'SMART support is: Available' in stdout_info or 'SMART support is: Enabled' in stdout_info:
            disk_info['smart_support'] = True
    
    if not disk_info['smart_support']:
        disk_info['health_status'] = 'S.M.A.R.T. desteklenmiyor'
        return disk_info
    
    # Sağlık durumunu kontrol et (-H parametresi)
    stdout_health, stderr_health, retcode_health = run_command(
        ["sudo", "smartctl", "-H", device_path],
        timeout=10
    )
    
    if retcode_health == 0 and stdout_health:
        if "PASSED" in stdout_health.upper():
            disk_info['health_status'] = 'PASSED'
        elif "OK" in stdout_health.upper():
            disk_info['health_status'] = 'OK'
        else:
            # Durum satırını bul
            for line in stdout_health.split('\n'):
                if 'test result' in line.lower():
                    disk_info['health_status'] = line.split(':')[-1].strip()
                    break
    else:
        if "unavailable" in stderr_health.lower() or "unable" in stderr_health.lower():
            disk_info['health_status'] = 'Kontrol edilemedi (Yetki veya uyumluluk sorunu)'
        else:
            disk_info['health_status'] = 'FAILED'
    
    # Detaylı S.M.A.R.T. değerlerini al (-A parametresi)
    stdout_attrs, stderr_attrs, retcode_attrs = run_command(
        ["sudo", "smartctl", "-A", device_path],
        timeout=10
    )
    
    if retcode_attrs == 0 and stdout_attrs:
        # Sıcaklık
        temp_match = re.search(r'194 Temperature.*\s+(\d+)', stdout_attrs)
        if temp_match:
            temp = int(temp_match.group(1))
            disk_info['temperature'] = f"{temp}°C"
            
            # Sıcaklık uyarıları
            if temp > 60:
                disk_info['warnings'].append(f"⚠️  Yüksek sıcaklık: {temp}°C (normal: <50°C)")
            elif temp > 50:
                disk_info['warnings'].append(f"⚡ Sıcaklık yükselmiş: {temp}°C")
        
        # Çalışma saati
        hours_match = re.search(r'9 Power_On_Hours.*\s+(\d+)', stdout_attrs)
        if hours_match:
            hours = int(hours_match.group(1))
            disk_info['power_on_hours'] = f"{hours} saat ({hours // 24} gün)"
            
            # Ömür uyarıları
            if hours > 43800:  # 5 yıl
                disk_info['warnings'].append(f"🕐 Disk yaşlı: {hours // 8760} yıl kullanılmış")
        
        # Açma-kapama döngüsü
        cycle_match = re.search(r'12 Power_Cycle_Count.*\s+(\d+)', stdout_attrs)
        if cycle_match:
            disk_info['power_cycle_count'] = cycle_match.group(1)
        
        # Yeniden tahsis edilmiş sektörler (ÖNEMLİ!)
        realloc_match = re.search(r'5 Reallocated_Sector_Ct.*\s+(\d+)', stdout_attrs)
        if realloc_match:
            realloc = int(realloc_match.group(1))
            disk_info['reallocated_sectors'] = str(realloc)
            
            if realloc > 0:
                disk_info['warnings'].append(
                    f"⚠️  KRİTİK: {realloc} sektör yeniden tahsis edilmiş! "
                    f"Disk arızalanıyor olabilir, yedek alın!"
                )
        
        # SSD için Wear Leveling
        wear_match = re.search(r'177 Wear_Leveling_Count.*\s+(\d+)', stdout_attrs)
        if wear_match:
            wear = int(wear_match.group(1))
            disk_info['wear_leveling'] = f"{wear}%"
            
            if wear < 10:
                disk_info['warnings'].append(
                    f"⚠️  SSD ömrü azaldı: %{wear} kaldı. Değiştirme zamanı yaklaşıyor."
                )
        
        # Bekleyen sektörler
        pending_match = re.search(r'197 Current_Pending_Sector.*\s+(\d+)', stdout_attrs)
        if pending_match:
            pending = int(pending_match.group(1))
            if pending > 0:
                disk_info['warnings'].append(
                    f"⚠️  {pending} bekleyen hatalı sektör var!"
                )
    
    return disk_info


def get_disk_io_stats() -> List[Dict[str, str]]:
    """
    Disk I/O (Giriş/Çıkış) istatistiklerini alır.
    
    Hangi diskler ne kadar veri okuyor/yazıyor?
    Bu bilgi performans sorunlarını tespit etmeye yardımcı olur.
    
    Returns:
        List[Dict]: Her disk için I/O istatistikleri
        
    Examples:
        >>> io_stats = get_disk_io_stats()
        >>> for disk in io_stats:
        ...     print(f"{disk['device']}: {disk['read_mb']} MB okundu, {disk['written_mb']} MB yazıldı")
    """
    stdout, stderr, retcode = run_command(["iostat", "-d", "-m"], timeout=5)
    
    if retcode != 0:
        log.warning("iostat komutu bulunamadı. sysstat paketini kurun: sudo apt install sysstat")
        return []
    
    io_stats = []
    lines = stdout.strip().split('\n')
    
    # Başlık satırlarını atla, sadece veri satırlarını al
    data_started = False
    for line in lines:
        if line.startswith('Device'):
            data_started = True
            continue
        
        if data_started and line.strip():
            parts = line.split()
            if len(parts) >= 6:
                io_stats.append({
                    'device': parts[0],
                    'read_mb': parts[2],
                    'written_mb': parts[3],
                    'tps': parts[1]  # Transfers per second
                })
    
    return io_stats


def check_disk_fragmentation(mount_point: str = '/') -> Dict[str, str]:
    """
    Disk parçalanmasını kontrol eder (sadece ext4 için).
    
    Not: Linux dosya sistemleri (ext4, btrfs, xfs) genellikle otomatik olarak 
    parçalanmayı minimize eder. Windows'taki kadar önemli değildir.
    
    Args:
        mount_point: Kontrol edilecek bağlama noktası
    
    Returns:
        Dict: Parçalanma yüzdesi ve durumu
    """
    result = {
        'mount_point': mount_point,
        'fragmentation': 'N/A',
        'recommendation': 'N/A'
    }
    
    # e4defrag komutuyla kontrol et (sadece ext4 için)
    stdout, stderr, retcode = run_command(["sudo", "e4defrag", "-c", mount_point], timeout=30)
    
    if retcode == 0 and stdout:
        # Çıktıdan parçalanma yüzdesini bul
        frag_match = re.search(r'fragmentation:\s+([\d.]+)%', stdout)
        if frag_match:
            frag_percent = float(frag_match.group(1))
            result['fragmentation'] = f"{frag_percent}%"
            
            if frag_percent > 30:
                result['recommendation'] = "Yüksek parçalanma. 'sudo e4defrag /' komutuyla birleştirme yapabilirsiniz."
            elif frag_percent > 10:
                result['recommendation'] = "Orta seviye parçalanma. İzlemeye devam edin."
            else:
                result['recommendation'] = "Parçalanma seviyesi normal, işlem gerekmez."
    
    return result


def get_nvme_health() -> List[Dict[str, any]]:
    """
    NVMe SSD'lerin özel sağlık metriklerini alır.
    
    NVMe diskler farklı S.M.A.R.T. parametreleri kullanır ve 
    daha detaylı sağlık bilgileri sağlar.
    
    Returns:
        List[Dict]: Her NVMe disk için sağlık bilgileri
    """
    nvme_disks = []
    
    # NVMe diskleri bul
    stdout, stderr, retcode = run_command(["lsblk", "-dno", "NAME,TYPE"], timeout=5)
    
    if retcode == 0:
        for line in stdout.strip().split('\n'):
            if 'disk' in line:
                disk_name = line.split()[0]
                if disk_name.startswith('nvme'):
                    device_path = f"/dev/{disk_name}"
                    nvme_info = _get_nvme_smart(device_path)
                    if nvme_info:
                        nvme_disks.append(nvme_info)
    
    return nvme_disks


def _get_nvme_smart(device_path: str) -> Optional[Dict[str, any]]:
    """NVMe disk için özel S.M.A.R.T. bilgilerini alır."""
    
    stdout, stderr, retcode = run_command(
        ["sudo", "smartctl", "-a", device_path],
        timeout=10
    )
    
    if retcode != 0:
        return None
    
    nvme_info = {
        'device': device_path,
        'model': 'N/A',
        'capacity': 'N/A',
        'temperature': 'N/A',
        'percentage_used': 'N/A',  # NVMe'ye özel
        'available_spare': 'N/A',  # NVMe'ye özel
        'data_written': 'N/A',
        'data_read': 'N/A',
        'warnings': []
    }
    
    # Model
    model_match = re.search(r'Model Number:\s+(.+)', stdout)
    if model_match:
        nvme_info['model'] = model_match.group(1).strip()
    
    # Kapasite
    capacity_match = re.search(r'Namespace 1 Size/Capacity:\s+(.+)', stdout)
    if capacity_match:
        nvme_info['capacity'] = capacity_match.group(1).strip()
    
    # Sıcaklık
    temp_match = re.search(r'Temperature:\s+(\d+)\s+Celsius', stdout)
    if temp_match:
        temp = int(temp_match.group(1))
        nvme_info['temperature'] = f"{temp}°C"
        if temp > 70:
            nvme_info['warnings'].append(f"⚠️  Yüksek sıcaklık: {temp}°C")
    
    # Kullanılan yüzde (SSD ömrü)
    used_match = re.search(r'Percentage Used:\s+(\d+)%', stdout)
    if used_match:
        used = int(used_match.group(1))
        nvme_info['percentage_used'] = f"{used}%"
        if used > 80:
            nvme_info['warnings'].append(f"⚠️  SSD ömrü azaldı: %{used} kullanılmış")
    
    # Yedek alan
    spare_match = re.search(r'Available Spare:\s+(\d+)%', stdout)
    if spare_match:
        spare = int(spare_match.group(1))
        nvme_info['available_spare'] = f"{spare}%"
        if spare < 10:
            nvme_info['warnings'].append(f"⚠️  Yedek alan azaldı: %{spare} kaldı")
    
    # Yazılan veri
    written_match = re.search(r'Data Units Written:\s+[\d,]+\s+\[(.+?)\]', stdout)
    if written_match:
        nvme_info['data_written'] = written_match.group(1).strip()
    
    # Okunan veri
    read_match = re.search(r'Data Units Read:\s+[\d,]+\s+\[(.+?)\]', stdout)
    if read_match:
        nvme_info['data_read'] = read_match.group(1).strip()
    
    return nvme_info


def estimate_disk_lifespan(disk_details: List[Dict]) -> List[Dict[str, str]]:
    """
    Disklerin tahmini kalan ömrünü hesaplar.
    
    Args:
        disk_details: check_smart_health() fonksiyonundan gelen disk bilgileri
    
    Returns:
        List[Dict]: Her disk için ömür tahmini
    """
    lifespan_estimates = []
    
    for disk in disk_details:
        estimate = {
            'device': disk.get('device', 'N/A'),
            'model': disk.get('model', 'N/A'),
            'estimated_lifespan': 'N/A',
            'recommendation': ''
        }
        
        # Çalışma saatine göre tahmin (ortalama disk ömrü: 5-7 yıl = ~50,000 saat)
        power_on_hours = disk.get('power_on_hours', 'N/A')
        if power_on_hours != 'N/A' and 'saat' in power_on_hours:
            try:
                hours = int(power_on_hours.split()[0])
                remaining_hours = 50000 - hours
                remaining_years = remaining_hours / 8760
                
                if remaining_years < 0:
                    estimate['estimated_lifespan'] = "Beklenen ömür aşıldı"
                    estimate['recommendation'] = "🔴 Diski acilen değiştirin ve yedek alın!"
                elif remaining_years < 1:
                    estimate['estimated_lifespan'] = f"~{int(remaining_years * 12)} ay"
                    estimate['recommendation'] = "🟠 Yedek almayı planlamalısınız"
                else:
                    estimate['estimated_lifespan'] = f"~{remaining_years:.1f} yıl"
                    estimate['recommendation'] = "🟢 Disk sağlıklı görünüyor"
            except (ValueError, IndexError):
                pass
        
        # Yeniden tahsis edilmiş sektörler varsa ömür tahmini değişir
        reallocated = disk.get('reallocated_sectors', 'N/A')
        if reallocated != 'N/A' and reallocated != '0':
            estimate['recommendation'] = "🔴 KRİTİK: Disk arızalanıyor! Acil yedek alın!"
        
        # SSD için wear leveling kontrolü
        wear = disk.get('wear_leveling', 'N/A')
        if wear != 'N/A' and '%' in wear:
            try:
                wear_percent = int(wear.replace('%', ''))
                if wear_percent < 20:
                    estimate['recommendation'] = "🟠 SSD ömrü azalıyor, yedekleme yapın"
            except ValueError:
                pass
        
        lifespan_estimates.append(estimate)
    
    return lifespan_estimates


def get_filesystem_errors(mount_point: str = '/') -> Dict[str, any]:
    """
    Dosya sistemi hatalarını dmesg ve syslog'dan tarar.
    
    Args:
        mount_point: Kontrol edilecek bağlama noktası
    
    Returns:
        Dict: Bulunan hata sayısı ve örnekler
    """
    result = {
        'error_count': 0,
        'warning_count': 0,
        'sample_errors': []
    }
    
    # dmesg'den hata ara
    stdout, stderr, retcode = run_command(["sudo", "dmesg", "-T"], timeout=10)
    
    if retcode == 0:
        error_keywords = ['I/O error', 'EXT4-fs error', 'Buffer I/O error', 'SMART error']
        warning_keywords = ['EXT4-fs warning', 'disk warning']
        
        for line in stdout.split('\n'):
            line_lower = line.lower()
            
            if any(keyword.lower() in line_lower for keyword in error_keywords):
                result['error_count'] += 1
                if len(result['sample_errors']) < 5:
                    # Zaman damgasını da al
                    result['sample_errors'].append(line.strip())
            
            if any(keyword.lower() in line_lower for keyword in warning_keywords):
                result['warning_count'] += 1
    
    return result