"""
Disk ve Depolama Sağlığı Analiz Modülü
======================================

S.M.A.R.T. durumu, disk ömrü, sıcaklık, performans metrikleri ve 
depolama alanı kontrolü.

Features:
    - S.M.A.R.T. sağlık durumu kontrolü
    - Disk sıcaklık ve ömür analizi
    - Kritik parametre takibi (reallocated sectors, pending sectors)
    - SSD/HDD algılama ve özel kontroller
    - Disk I/O performans metrikleri
    - RAID durumu kontrolü
    - Disk bağlantı türü (SATA, NVMe, USB) tespiti

Author: ozturu68
Version: 0.4.0
Date: 2025-10-29
License: MIT
"""

import re
import logging
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum
from dataclasses import dataclass, asdict

from ..utils.command_runner import (
    run_command, 
    is_command_available,
    safe_command_output
)

# Logger
log = logging.getLogger(__name__)


# =============================================================================
# ENUM VE DATACLASS TANIMLARI
# =============================================================================

class HealthStatus(Enum):
    """Disk sağlık durumu enum'ı."""
    PASSED = "İYİ"
    WARNING = "UYARI"
    FAILED = "SORUNLU"
    UNKNOWN = "BİLİNMİYOR"
    NOT_SUPPORTED = "DESTEKLENMEZ"
    NO_ACCESS = "ERİŞİLEMEZ"
    PERMISSION_DENIED = "YETKİ GEREKLİ"
    NOT_AVAILABLE = "KONTROL EDİLEMEDİ"


class DiskType(Enum):
    """Disk tipi enum'ı."""
    SSD = "SSD"
    HDD = "HDD"
    NVME = "NVMe"
    USB = "USB"
    UNKNOWN = "Bilinmiyor"


@dataclass
class DiskInfo:
    """Disk bilgi sınıfı."""
    device: str
    health_status: str
    disk_type: str
    smart_enabled: bool
    temperature: Optional[int] = None
    power_on_hours: Optional[int] = None
    power_cycle_count: Optional[int] = None
    reallocated_sectors: Optional[int] = None
    pending_sectors: Optional[int] = None
    uncorrectable_errors: Optional[int] = None
    wear_leveling: Optional[int] = None  # SSD için
    total_lbas_written: Optional[int] = None  # SSD için
    model: Optional[str] = None
    serial: Optional[str] = None
    firmware: Optional[str] = None
    capacity: Optional[str] = None
    interface: Optional[str] = None
    warnings: List[str] = None
    
    def __post_init__(self):
        if self.warnings is None:
            self.warnings = []
    
    def to_dict(self) -> Dict[str, Any]:
        """Dataclass'ı dictionary'e çevirir."""
        return asdict(self)


# =============================================================================
# YARDIMCI FONKSİYONLAR
# =============================================================================

def _detect_disk_type(device: str, smart_output: str) -> DiskType:
    """
    Disk tipini (SSD/HDD/NVMe/USB) algılar.
    
    Args:
        device: Disk yolu (örn: /dev/sda)
        smart_output: smartctl çıktısı
        
    Returns:
        DiskType: Algılanan disk tipi
    """
    output_lower = smart_output.lower()
    
    # NVMe kontrolü
    if 'nvme' in device.lower() or 'nvme' in output_lower:
        return DiskType.NVME
    
    # USB kontrolü
    if 'usb' in output_lower or '/dev/sd' in device and 'usb' in output_lower:
        return DiskType.USB
    
    # SSD kontrolü - birden fazla gösterge
    ssd_indicators = [
        'solid state',
        'ssd',
        'rotation rate:    solid state device',
        'rotation rate:    0 rpm',
        'media type:       solid state',
        'trim command:     available'
    ]
    
    for indicator in ssd_indicators:
        if indicator in output_lower:
            return DiskType.SSD
    
    # HDD kontrolü - dönüş hızı varsa HDD'dir
    if 'rotation rate:' in output_lower and 'rpm' in output_lower:
        rpm_match = re.search(r'rotation rate:\s*(\d+)\s*rpm', output_lower)
        if rpm_match and int(rpm_match.group(1)) > 0:
            return DiskType.HDD
    
    # Varsayılan: bilinmiyor
    return DiskType.UNKNOWN


def _parse_smart_attribute(line: str, attr_name: str) -> Optional[int]:
    """
    S.M.A.R.T. çıktısından belirli bir özelliği parse eder.
    
    Args:
        line: S.M.A.R.T. satırı
        attr_name: Aranacak özellik adı
        
    Returns:
        Optional[int]: Bulunan değer veya None
    """
    if attr_name.lower() in line.lower():
        # Satır formatı genellikle: "ID# ATTRIBUTE_NAME ... RAW_VALUE"
        parts = line.split()
        if len(parts) >= 10:
            try:
                # Son sütun genellikle RAW_VALUE'dur
                return int(parts[-1])
            except ValueError:
                pass
    return None


def _evaluate_disk_health(disk_info: DiskInfo) -> Tuple[str, List[str]]:
    """
    Disk parametrelerine göre sağlık durumunu değerlendirir.
    
    Args:
        disk_info: Disk bilgileri
        
    Returns:
        Tuple[str, List[str]]: (sağlık_durumu, uyarı_listesi)
    """
    warnings = []
    status = HealthStatus.PASSED.value
    
    # 1. Reallocated Sectors kontrolü (KRİTİK)
    if disk_info.reallocated_sectors is not None:
        if disk_info.reallocated_sectors > 0:
            warnings.append(
                f"⚠️  {disk_info.reallocated_sectors} yeniden tahsis edilmiş sektör bulundu. "
                "Disk yüzeyi hasar görebilir."
            )
            status = HealthStatus.WARNING.value
        
        if disk_info.reallocated_sectors > 10:
            status = HealthStatus.FAILED.value
    
    # 2. Pending Sectors kontrolü (ÇOK KRİTİK)
    if disk_info.pending_sectors is not None and disk_info.pending_sectors > 0:
        warnings.append(
            f"🔴 {disk_info.pending_sectors} bekleyen (unstable) sektör var! "
            "Veri kaybı riski yüksek!"
        )
        status = HealthStatus.FAILED.value
    
    # 3. Uncorrectable Errors (KRİTİK)
    if disk_info.uncorrectable_errors is not None and disk_info.uncorrectable_errors > 0:
        warnings.append(
            f"🔴 {disk_info.uncorrectable_errors} düzeltilemeyen hata! "
            "Diskte ciddi sorun var."
        )
        status = HealthStatus.FAILED.value
    
    # 4. Sıcaklık kontrolü
    if disk_info.temperature is not None:
        if disk_info.temperature > 60:
            warnings.append(
                f"🌡️  Disk sıcaklığı yüksek: {disk_info.temperature}°C "
                "(Önerilen: <50°C)"
            )
            if status == HealthStatus.PASSED.value:
                status = HealthStatus.WARNING.value
        
        if disk_info.temperature > 70:
            warnings.append("🔥 Disk aşırı ısınıyor! Soğutma gerekli.")
            status = HealthStatus.FAILED.value
    
    # 5. SSD için Wear Leveling kontrolü
    if disk_info.disk_type == DiskType.SSD.value and disk_info.wear_leveling is not None:
        remaining = disk_info.wear_leveling
        if remaining < 10:
            warnings.append(
                f"⚠️  SSD ömrü %{remaining} kaldı. Yedekleme yapın!"
            )
            status = HealthStatus.WARNING.value
        
        if remaining < 5:
            warnings.append("🔴 SSD ömrü kritik seviyede!")
            status = HealthStatus.FAILED.value
    
    # 6. Power-on hours kontrolü (bilgi amaçlı)
    if disk_info.power_on_hours is not None:
        hours = disk_info.power_on_hours
        years = hours / (24 * 365)
        
        if years > 5:
            warnings.append(
                f"ℹ️  Disk {years:.1f} yıldır kullanımda ({hours:,} saat). "
                "Yaşlanma belirtileri gösterebilir."
            )
    
    return status, warnings


# =============================================================================
# ANA FONKSİYONLAR
# =============================================================================

def check_smart_health() -> Dict[str, Any]:
    """
    Tüm fiziksel disklerin S.M.A.R.T. sağlık durumunu kontrol eder.
    
    S.M.A.R.T. (Self-Monitoring, Analysis and Reporting Technology):
        - Disk arızalarını öngörmeye yardımcı olur
        - Önemli parametreleri izler (hata oranları, sıcaklık, vb.)
        - Disk ömrü hakkında bilgi verir
    
    Returns:
        Dict[str, Any]: {
            'status': str,  # İYİ, SORUNLU, UYARI, KONTROL EDİLEMEDİ
            'failing_disks': List[str],  # Sorunlu disklerin listesi
            'warning_disks': List[str],  # Uyarı seviyesindeki diskler
            'disk_details': List[Dict],  # Her disk için detaylı bilgi
            'summary': Dict[str, int]  # Özet istatistikler
        }
    
    Examples:
        >>> health = check_smart_health()
        >>> if health['status'] == 'SORUNLU':
        ...     for disk in health['failing_disks']:
        ...         print(f"⚠️  {disk}")
        >>> 
        >>> # Disk detaylarına erişim
        >>> for disk in health['disk_details']:
        ...     print(f"{disk['device']}: {disk['temperature']}°C")
    
    Note:
        - Bu fonksiyon 'smartmontools' paketini gerektirir
        - Sudo yetkisi gerekebilir
        - Sanal diskler (loop, zram) otomatik filtrelenir
    """
    # smartctl komutunun varlığını kontrol et
    if not is_command_available("smartctl"):
        log.warning("smartctl komutu bulunamadı")
        return {
            "status": HealthStatus.NOT_AVAILABLE.value,
            "failing_disks": [],
            "warning_disks": [],
            "disk_details": [],
            "summary": {
                "total": 0,
                "healthy": 0,
                "warning": 0,
                "failed": 0,
                "not_checked": 1
            },
            "message": [
                "'smartmontools' paketi kurulu değil.",
                "Kurulum: sudo apt install smartmontools"
            ]
        }
    
    # Fiziksel diskleri listele
    stdout, stderr, retcode = run_command(
        ["lsblk", "-dno", "NAME,TYPE"], 
        timeout=10
    )
    
    if retcode != 0:
        log.error(f"Diskler listelenemedi: {stderr}")
        return {
            "status": HealthStatus.NOT_AVAILABLE.value,
            "failing_disks": [],
            "warning_disks": [],
            "disk_details": [],
            "summary": {
                "total": 0,
                "healthy": 0,
                "warning": 0,
                "failed": 0,
                "not_checked": 1
            },
            "message": [f"Diskler listelenemedi: {stderr.strip()}"]
        }
    
    # Fiziksel diskleri filtrele (loop, zram, vb. sanal diskleri atla)
    disk_names = []
    for line in stdout.strip().split('\n'):
        parts = line.split()
        if len(parts) < 2:
            continue
        
        name, dtype = parts[0], parts[1]
        
        # Sadece 'disk' tipindeki ve sanal olmayan diskleri al
        if 'disk' in dtype and not any(x in name for x in ['loop', 'zram', 'ram']):
            disk_names.append(name)
    
    if not disk_names:
        log.info("S.M.A.R.T. kontrol edilebilecek fiziksel disk bulunamadı")
        return {
            "status": HealthStatus.NOT_AVAILABLE.value,
            "failing_disks": [],
            "warning_disks": [],
            "disk_details": [],
            "summary": {
                "total": 0,
                "healthy": 0,
                "warning": 0,
                "failed": 0,
                "not_checked": 1
            },
            "message": ["S.M.A.R.T. kontrol edilebilecek fiziksel disk bulunamadı."]
        }
    
    # Her disk için S.M.A.R.T. analizi yap
    failing_disks = []
    warning_disks = []
    disk_details = []
    summary = {
        "total": len(disk_names),
        "healthy": 0,
        "warning": 0,
        "failed": 0,
        "not_checked": 0
    }
    
    for disk in disk_names:
        device_path = f"/dev/{disk}"
        log.debug(f"S.M.A.R.T. kontrolü yapılıyor: {device_path}")
        
        disk_info = _analyze_disk_smart(device_path)
        disk_details.append(disk_info.to_dict())
        
        # Kategorize et
        if disk_info.health_status == HealthStatus.FAILED.value:
            failing_disks.append(f"{device_path}: {disk_info.health_status}")
            summary['failed'] += 1
        elif disk_info.health_status == HealthStatus.WARNING.value:
            warning_disks.append(f"{device_path}: {disk_info.health_status}")
            summary['warning'] += 1
        elif disk_info.health_status == HealthStatus.PASSED.value:
            summary['healthy'] += 1
        else:
            summary['not_checked'] += 1
    
    # Genel durumu belirle
    overall_status = HealthStatus.PASSED.value
    if failing_disks:
        overall_status = HealthStatus.FAILED.value
    elif warning_disks:
        overall_status = HealthStatus.WARNING.value
    elif summary['not_checked'] == summary['total']:
        overall_status = HealthStatus.NOT_AVAILABLE.value
    
    return {
        "status": overall_status,
        "failing_disks": failing_disks,
        "warning_disks": warning_disks,
        "disk_details": disk_details,
        "summary": summary
    }


def _analyze_disk_smart(device: str) -> DiskInfo:
    """
    Tek bir disk için detaylı S.M.A.R.T. analizi yapar.
    
    Args:
        device: Disk yolu (örn: /dev/sda)
        
    Returns:
        DiskInfo: Disk detay bilgileri
    """
    disk_info = DiskInfo(
        device=device,
        health_status=HealthStatus.UNKNOWN.value,
        disk_type=DiskType.UNKNOWN.value,
        smart_enabled=False
    )
    
    # S.M.A.R.T. bilgisini al (sudo gerektirir)
    stdout, stderr, retcode = run_command(
        ["sudo", "smartctl", "-a", device],
        timeout=15,
        suppress_stderr=True
    )
    
    # Hata kontrolü
    if retcode == 127:
        disk_info.health_status = HealthStatus.NOT_AVAILABLE.value
        disk_info.warnings.append("smartctl komutu bulunamadı")
        return disk_info
    
    if retcode not in [0, 4]:  # 4 = bazı eşikler aşıldı ama hala okunabilir
        # Disk S.M.A.R.T. desteklemiyor veya erişim hatası
        if "Permission denied" in stderr or "Yetki" in stderr:
            disk_info.health_status = HealthStatus.PERMISSION_DENIED.value
        elif "SMART support is: Unavailable" in stdout or "SMART support is: Disabled" in stdout:
            disk_info.health_status = HealthStatus.NOT_SUPPORTED.value
        else:
            disk_info.health_status = HealthStatus.NO_ACCESS.value
        return disk_info
    
    disk_info.smart_enabled = True
    
    # Disk tipini algıla
    disk_info.disk_type = _detect_disk_type(device, stdout).value
    
    # Temel sağlık durumu
    health_match = re.search(
        r'SMART overall-health self-assessment test result:\s*(\w+)', 
        stdout,
        re.IGNORECASE
    )
    if health_match:
        status_text = health_match.group(1).upper()
        if status_text == 'PASSED':
            disk_info.health_status = HealthStatus.PASSED.value
        else:
            disk_info.health_status = HealthStatus.FAILED.value
    
    # Model, Serial, Firmware
    model_match = re.search(r'(?:Device Model|Model Number|Product):\s*(.+)', stdout)
    if model_match:
        disk_info.model = model_match.group(1).strip()
    
    serial_match = re.search(r'Serial Number:\s*(.+)', stdout)
    if serial_match:
        disk_info.serial = serial_match.group(1).strip()
    
    firmware_match = re.search(r'Firmware Version:\s*(.+)', stdout)
    if firmware_match:
        disk_info.firmware = firmware_match.group(1).strip()
    
    # Kapasite
    capacity_match = re.search(r'User Capacity:\s*([^\[]+)', stdout)
    if capacity_match:
        disk_info.capacity = capacity_match.group(1).strip()
    
    # Interface
    interface_match = re.search(r'SATA Version is:\s*(.+)', stdout)
    if interface_match:
        disk_info.interface = "SATA " + interface_match.group(1).strip()
    elif 'nvme' in device.lower():
        disk_info.interface = "NVMe"
    
    # S.M.A.R.T. özelliklerini parse et
    for line in stdout.split('\n'):
        # Sıcaklık
        if 'temperature' in line.lower() or 'airflow_temperature' in line.lower():
            temp = _parse_smart_attribute(line, 'temperature')
            if temp and temp < 100:  # Mantıklı bir sıcaklık değeri
                disk_info.temperature = temp
        
        # Power-on Hours
        if 'power_on_hours' in line.lower() or 'power-on hours' in line.lower():
            hours = _parse_smart_attribute(line, 'power_on_hours')
            if hours:
                disk_info.power_on_hours = hours
        
        # Power Cycle Count
        if 'power_cycle_count' in line.lower():
            cycles = _parse_smart_attribute(line, 'power_cycle_count')
            if cycles:
                disk_info.power_cycle_count = cycles
        
        # Reallocated Sectors (KRİTİK)
        if 'reallocated_sector' in line.lower():
            realloc = _parse_smart_attribute(line, 'reallocated_sector')
            if realloc is not None:
                disk_info.reallocated_sectors = realloc
        
        # Current Pending Sectors (ÇOK KRİTİK)
        if 'current_pending_sector' in line.lower():
            pending = _parse_smart_attribute(line, 'current_pending_sector')
            if pending is not None:
                disk_info.pending_sectors = pending
        
        # Offline Uncorrectable
        if 'offline_uncorrectable' in line.lower():
            uncorr = _parse_smart_attribute(line, 'offline_uncorrectable')
            if uncorr is not None:
                disk_info.uncorrectable_errors = uncorr
        
        # SSD: Wear Leveling Count
        if 'wear_leveling_count' in line.lower() or 'percentage used' in line.lower():
            wear = _parse_smart_attribute(line, 'wear_leveling')
            if wear is not None:
                disk_info.wear_leveling = wear
        
        # SSD: Total LBAs Written
        if 'total_lbas_written' in line.lower():
            lbas = _parse_smart_attribute(line, 'total_lbas_written')
            if lbas is not None:
                disk_info.total_lbas_written = lbas
    
    # Sağlık durumunu yeniden değerlendir
    evaluated_status, warnings = _evaluate_disk_health(disk_info)
    disk_info.health_status = evaluated_status
    disk_info.warnings.extend(warnings)
    
    return disk_info


# =============================================================================
# DISK I/O İSTATİSTİKLERİ
# =============================================================================

def get_disk_io_stats(interval: float = 1.0) -> List[Dict[str, Any]]:
    """
    Disk I/O istatistiklerini toplar (okuma/yazma hızları).
    
    Args:
        interval: Ölçüm aralığı (saniye, varsayılan: 1.0)
    
    Returns:
        List[Dict[str, Any]]: Her disk için I/O istatistikleri
            {
                'device': str,
                'read_mb_per_sec': float,
                'write_mb_per_sec': float,
                'read_ops_per_sec': float,
                'write_ops_per_sec': float
            }
    
    Examples:
        >>> stats = get_disk_io_stats()
        >>> for disk in stats:
        ...     print(f"{disk['device']}: R={disk['read_mb_per_sec']:.2f} MB/s")
    
    Note:
        Bu fonksiyon psutil kütüphanesini gerektirir.
    """
    try:
        import psutil
        import time
        
        # İlk ölçüm
        io_counters_1 = psutil.disk_io_counters(perdisk=True)
        
        # Bekleme
        time.sleep(interval)
        
        # İkinci ölçüm
        io_counters_2 = psutil.disk_io_counters(perdisk=True)
        
        disk_stats = []
        
        for disk_name in io_counters_1:
            # Fiziksel diskleri filtrele
            if any(x in disk_name for x in ['loop', 'zram', 'ram']):
                continue
            
            c1 = io_counters_1[disk_name]
            c2 = io_counters_2[disk_name]
            
            # Fark hesapla (per second)
            read_bytes_per_sec = (c2.read_bytes - c1.read_bytes) / interval
            write_bytes_per_sec = (c2.write_bytes - c1.write_bytes) / interval
            read_ops_per_sec = (c2.read_count - c1.read_count) / interval
            write_ops_per_sec = (c2.write_count - c1.write_count) / interval
            
            disk_stats.append({
                'device': disk_name,
                'read_mb_per_sec': read_bytes_per_sec / (1024 * 1024),
                'write_mb_per_sec': write_bytes_per_sec / (1024 * 1024),
                'read_ops_per_sec': read_ops_per_sec,
                'write_ops_per_sec': write_ops_per_sec,
                'read_total_mb': c2.read_bytes / (1024 * 1024),
                'write_total_mb': c2.write_bytes / (1024 * 1024),
                'busy_time_ms': c2.busy_time
            })
        
        return disk_stats
        
    except ImportError:
        log.error("psutil kütüphanesi bulunamadı")
        return []
    except Exception as e:
        log.error(f"Disk I/O istatistikleri alınamadı: {e}")
        return []


# =============================================================================
# RAID DURUMU KONTROLÜ
# =============================================================================

def check_raid_status() -> Dict[str, Any]:
    """
    Software RAID (mdadm) durumunu kontrol eder.
    
    Returns:
        Dict[str, Any]: RAID durumu bilgileri
    
    Examples:
        >>> raid = check_raid_status()
        >>> if raid['arrays']:
        ...     for array in raid['arrays']:
        ...         print(f"{array['device']}: {array['state']}")
    """
    if not is_command_available("mdadm"):
        return {
            "available": False,
            "message": "mdadm kurulu değil (Software RAID kullanılmıyor)"
        }
    
    # /proc/mdstat dosyasını kontrol et
    stdout, stderr, retcode = run_command(["cat", "/proc/mdstat"], timeout=5)
    
    if retcode != 0 or not stdout.strip():
        return {
            "available": True,
            "arrays": [],
            "message": "RAID array bulunamadı"
        }
    
    arrays = []
    current_array = None
    
    for line in stdout.split('\n'):
        line = line.strip()
        
        # Array satırı: md0 : active raid1 sda1[0] sdb1[1]
        if line.startswith('md'):
            parts = line.split()
            if len(parts) >= 4:
                current_array = {
                    'device': f"/dev/{parts[0]}",
                    'state': parts[2],
                    'level': parts[3],
                    'disks': []
                }
                arrays.append(current_array)
        
        # Disk durumu satırı
        elif current_array and '[' in line and ']' in line:
            # Disk bilgilerini parse et
            disk_matches = re.findall(r'(\w+)\[(\d+)\](?:\((\w+)\))?', line)
            for disk, num, status in disk_matches:
                current_array['disks'].append({
                    'name': disk,
                    'number': int(num),
                    'status': status if status else 'active'
                })
    
    return {
        "available": True,
        "arrays": arrays,
        "total_arrays": len(arrays)
    }


# =============================================================================
# ÖRNEK KULLANIM
# =============================================================================

if __name__ == "__main__":
    # Test
    import json
    
    logging.basicConfig(level=logging.DEBUG)
    
    print("=== Depolama Sağlık Kontrolü Test ===\n")
    
    # S.M.A.R.T. kontrolü
    print("1. S.M.A.R.T. Sağlık Kontrolü:")
    health = check_smart_health()
    print(json.dumps(health, indent=2, ensure_ascii=False))
    
    print("\n2. Disk I/O İstatistikleri:")
    io_stats = get_disk_io_stats()
    print(json.dumps(io_stats, indent=2, ensure_ascii=False))
    
    print("\n3. RAID Durumu:")
    raid = check_raid_status()
    print(json.dumps(raid, indent=2, ensure_ascii=False))
    
    print("\n=== Test Tamamlandı ===")