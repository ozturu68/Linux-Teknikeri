"""
Ağ Port Tarama Modülü
======================

Sistemde dinlemede olan (LISTEN) ağ portlarını tarar ve analiz eder.

Fonksiyonlar:
    get_listening_ports()  - Ana fonksiyon (port tarama)

Özellikler:
    - ss komutu (modern, hızlı) veya netstat (fallback)
    - Process bilgisi (PID, kullanıcı)
    - Privileged port tespiti (< 1024)
    - Public/localhost ayrımı
    - Risk analizi
    - Type-safe (PortInfo dataclass)

Desteklenen Komutlar:
    1. ss -tulpn (tercih edilen, hızlı)
    2. netstat -tulpn (fallback)

Author: ozturu68
Version: 0.5.0
Date: 2025-11-01
License: MIT
"""

import re
import logging
from typing import List, Dict, Optional, Any

# Local imports
from .models import PortInfo
from ...utils.command_runner import (
    run_command,
    is_command_available
)

# Logger
log = logging.getLogger(__name__)


# =============================================================================
# ANA FONKSİYON
# =============================================================================

def get_listening_ports() -> List[Dict[str, Any]]:
    """
    Sistemde dinlemede olan (LISTEN) ağ portlarını listeler.
    
    ss komutu tercih edilir (modern ve hızlı). Mevcut değilse netstat
    kullanılır. Her port için detaylı bilgi (protocol, address, port, process,
    PID) döndürülür.
    
    Returns:
        List[Dict[str, Any]]: Her port için PortInfo dict formatında bilgi
            {
                'protocol': str,          # tcp, udp, tcp6, udp6
                'address': str,           # 0.0.0.0, 127.0.0.1, ::, vb.
                'port': str,              # Port numarası
                'process': str,           # Process adı
                'pid': Optional[int],     # Process ID
                'user': Optional[str],    # Process sahibi
                'is_privileged': bool     # Port < 1024
            }
    
    Examples:
        >>> from linux_teknikeri.checks.security import get_listening_ports
        >>> 
        >>> # Temel kullanım
        >>> ports = get_listening_ports()
        >>> print(f"{len(ports)} port bulundu")
        15 port bulundu
        >>> 
        >>> # Privileged portları filtrele
        >>> privileged = [p for p in ports if p['is_privileged']]
        >>> for port in privileged:
        ...     print(f"Privileged: {port['port']} - {port['process']}")
        Privileged: 22 - sshd
        Privileged: 80 - nginx
        >>> 
        >>> # Public portları bul
        >>> public_ports = [p for p in ports if p['address'] in ['0.0.0.0', '::', '[::]']]
        >>> print(f"{len(public_ports)} public port bulundu")
        5 public port bulundu
        >>> 
        >>> # Risk analizi
        >>> high_risk = [p for p in ports if PortInfo(**p).get_security_risk() == 'HIGH']
        >>> for port in high_risk:
        ...     print(f"⚠️  Yüksek risk: {port['port']}")
    
    Performance:
        - ss komutu: ~1-3 saniye
        - netstat komutu: ~2-5 saniye
    
    Note:
        - ss komutu tercih edilir (daha hızlı ve modern)
        - Fallback olarak netstat kullanılır
        - Sudo yetkisi gerekebilir (process bilgisi için)
        - Hata durumunda boş liste döner (crash etmez)
    
    Raises:
        Herhangi bir exception raise etmez, hataları log'lar ve boş liste döner.
    
    See Also:
        - PortInfo: Döndürülen veri modeli
        - PortInfo.get_security_risk(): Risk seviyesi hesaplama
        - PortInfo.is_public(): Public port kontrolü
    """
    log.info("Port taraması başlatılıyor...")
    ports: List[Dict[str, Any]] = []
    
    # ss komutu daha modern ve hızlıdır
    if is_command_available("ss"):
        log.debug("ss komutu kullanılıyor")
        ports = _scan_with_ss()
    else:
        # Fallback: netstat kullan
        log.info("ss komutu bulunamadı, netstat kullanılıyor")
        ports = _scan_with_netstat()
    
    log.info(f"Port taraması tamamlandı: {len(ports)} port bulundu")
    return ports


# =============================================================================
# HELPER FUNCTIONS - SS KOMUTU
# =============================================================================

def _scan_with_ss() -> List[Dict[str, Any]]:
    """
    ss komutu ile port taraması yapar.
    
    ss (socket statistics) modern ve hızlı bir network monitoring tool'dur.
    netstat'a göre daha hızlıdır ve daha detaylı bilgi verir.
    
    Returns:
        List[Dict[str, Any]]: Port bilgileri listesi
    
    Command:
        sudo ss -tulpn
            -t: TCP portları
            -u: UDP portları
            -l: LISTEN durumundaki portlar
            -p: Process bilgisi
            -n: Numeric (adres çözümleme yapma, hızlı)
    
    Output Format:
        Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
        tcp   LISTEN 0      128    0.0.0.0:22          0.0.0.0:*     users:(("sshd",pid=1234,fd=3))
    
    Note:
        - sudo gerektirir (process bilgisi için)
        - Hata durumunda boş liste döner
    """
    ports: List[Dict[str, Any]] = []
    
    try:
        stdout, stderr, retcode = run_command(
            ["sudo", "ss", "-tulpn"],
            timeout=10,
            suppress_stderr=True
        )
        
        if retcode != 0:
            log.error(f"ss komutu başarısız (retcode: {retcode}): {stderr}")
            return []
        
        # ss çıktısını parse et
        for line in stdout.strip().split('\n'):
            # İlk satır (başlık) atla
            if line.startswith('Netid') or line.startswith('State'):
                continue
            
            # Boş satırları atla
            if not line.strip():
                continue
            
            # Parse et
            port_info = _parse_ss_line(line)
            if port_info:
                ports.append(port_info.to_dict())
    
    except Exception as e:
        log.error(f"ss komutu çalıştırma hatası: {e}", exc_info=True)
        return []
    
    return ports


def _parse_ss_line(line: str) -> Optional[PortInfo]:
    """
    ss komutunun bir çıktı satırını parse eder.
    
    Args:
        line: ss komutu çıktı satırı
    
    Returns:
        Optional[PortInfo]: Parse edilen port bilgisi veya None
    
    Format:
        Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
        tcp   LISTEN 0      128    0.0.0.0:22          0.0.0.0:*     users:(("sshd",pid=1234,fd=3))
    
    Note:
        Hatalı satırlar None döndürür (log'lanır ama crash etmez).
    """
    try:
        # ss çıktısı: Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
        parts = line.split()
        if len(parts) < 5:
            return None
        
        protocol = parts[0]  # tcp, udp, tcp6, udp6
        local_addr = parts[4]  # 0.0.0.0:80 veya [::]:80
        
        # Adres ve portu ayır
        if ':' not in local_addr:
            return None
        
        try:
            addr, port = local_addr.rsplit(':', 1)
            # IPv6 adreslerini temizle: [::]:80 -> ::
            addr = addr.strip('[]')
        except ValueError:
            log.warning(f"Port parse hatası: {local_addr}")
            return None
        
        # İşlem adını ve PID'yi bul (varsa)
        process = ''
        pid: Optional[int] = None
        user: Optional[str] = None
        
        if len(parts) >= 7:
            process_info = parts[6]
            # Format: users:(("sshd",pid=1234,fd=3))
            proc_match = re.search(r'\("([^"]+)",pid=(\d+)', process_info)
            if proc_match:
                process = proc_match.group(1)
                try:
                    pid = int(proc_match.group(2))
                except ValueError:
                    pass
        
        # PortInfo dataclass oluştur
        port_info = PortInfo(
            protocol=protocol,
            address=addr,
            port=port,
            process=process,
            pid=pid,
            user=user
        )
        
        return port_info
    
    except Exception as e:
        log.warning(f"ss satırı parse edilemedi: {line} - Hata: {e}")
        return None


# =============================================================================
# HELPER FUNCTIONS - NETSTAT KOMUTU (FALLBACK)
# =============================================================================

def _scan_with_netstat() -> List[Dict[str, Any]]:
    """
    netstat komutu ile port taraması yapar (fallback).
    
    netstat eski ama yaygın bir network monitoring tool'dur.
    ss komutu tercih edilir, ama bulunamazsa netstat kullanılır.
    
    Returns:
        List[Dict[str, Any]]: Port bilgileri listesi
    
    Command:
        sudo netstat -tulpn
            -t: TCP portları
            -u: UDP portları
            -l: LISTEN durumundaki portlar
            -p: Process bilgisi
            -n: Numeric (adres çözümleme yapma)
    
    Output Format:
        Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program
        tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1234/sshd
    
    Note:
        - sudo gerektirir (process bilgisi için)
        - ss'e göre daha yavaştır
        - Hata durumunda boş liste döner
    """
    ports: List[Dict[str, Any]] = []
    
    try:
        stdout, stderr, retcode = run_command(
            ["sudo", "netstat", "-tulpn"],
            timeout=10,
            suppress_stderr=True
        )
        
        if retcode != 0:
            log.error(f"netstat komutu başarısız: {stderr}")
            return []
        
        # netstat çıktısını parse et
        for line in stdout.strip().split('\n'):
            # Sadece tcp/udp satırlarını işle
            if not line.startswith('tcp') and not line.startswith('udp'):
                continue
            
            # Parse et
            port_info = _parse_netstat_line(line)
            if port_info:
                ports.append(port_info.to_dict())
    
    except Exception as e:
        log.error(f"netstat komutu çalıştırma hatası: {e}", exc_info=True)
        return []
    
    return ports


def _parse_netstat_line(line: str) -> Optional[PortInfo]:
    """
    netstat komutunun bir çıktı satırını parse eder.
    
    Args:
        line: netstat komutu çıktı satırı
    
    Returns:
        Optional[PortInfo]: Parse edilen port bilgisi veya None
    
    Format:
        Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program
        tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1234/sshd
    
    Note:
        Hatalı satırlar None döndürür.
    """
    try:
        parts = line.split()
        if len(parts) < 4:
            return None
        
        protocol = parts[0]  # tcp, udp, tcp6, udp6
        local_addr = parts[3]  # 0.0.0.0:22
        
        # Adres ve portu ayır
        if ':' not in local_addr:
            return None
        
        try:
            addr, port = local_addr.rsplit(':', 1)
            addr = addr.strip('[]')
        except ValueError:
            return None
        
        # Process bilgisi (netstat formatı farklı)
        process = ''
        pid: Optional[int] = None
        
        if len(parts) >= 7:
            process_col = parts[6]
            # Format: 1234/sshd
            if '/' in process_col:
                try:
                    pid_str, process = process_col.split('/', 1)
                    pid = int(pid_str)
                except (ValueError, IndexError):
                    process = process_col.split('/')[-1]
        
        # PortInfo dataclass oluştur
        port_info = PortInfo(
            protocol=protocol,
            address=addr,
            port=port,
            process=process,
            pid=pid
        )
        
        return port_info
    
    except Exception as e:
        log.warning(f"netstat satırı parse edilemedi: {line} - Hata: {e}")
        return None


# =============================================================================
# HELPER FUNCTIONS - ANALİZ
# =============================================================================

def analyze_ports(ports: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Port listesini analiz eder ve özet bilgi döndürür (bonus fonksiyon).
    
    Args:
        ports: get_listening_ports() çıktısı
    
    Returns:
        Dict[str, Any]: Port analiz özeti
            {
                'total_count': int,
                'public_count': int,
                'localhost_count': int,
                'privileged_count': int,
                'tcp_count': int,
                'udp_count': int,
                'high_risk_count': int,
                'by_protocol': Dict[str, int],
                'by_risk': Dict[str, int],
                'top_processes': List[Tuple[str, int]]
            }
    
    Examples:
        >>> ports = get_listening_ports()
        >>> analysis = analyze_ports(ports)
        >>> print(f"Toplam: {analysis['total_count']}")
        >>> print(f"Public: {analysis['public_count']}")
        >>> print(f"Yüksek risk: {analysis['high_risk_count']}")
    
    Note:
        Bu fonksiyon opsiyoneldir, get_listening_ports() kullanımı için gerekli değil.
    """
    from collections import Counter
    
    analysis = {
        'total_count': len(ports),
        'public_count': 0,
        'localhost_count': 0,
        'privileged_count': 0,
        'tcp_count': 0,
        'udp_count': 0,
        'high_risk_count': 0,
        'by_protocol': {},
        'by_risk': {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0},
        'top_processes': []
    }
    
    if not ports:
        return analysis
    
    process_counter = Counter()
    
    for port_dict in ports:
        # PortInfo oluştur
        port = PortInfo(**port_dict)
        
        # Public/localhost
        if port.is_public():
            analysis['public_count'] += 1
        if port.is_localhost():
            analysis['localhost_count'] += 1
        
        # Privileged
        if port.is_privileged:
            analysis['privileged_count'] += 1
        
        # Protocol
        if port.protocol.startswith('tcp'):
            analysis['tcp_count'] += 1
        elif port.protocol.startswith('udp'):
            analysis['udp_count'] += 1
        
        # Risk
        risk = port.get_security_risk()
        analysis['by_risk'][risk] += 1
        if risk == 'HIGH':
            analysis['high_risk_count'] += 1
        
        # Process
        if port.process:
            process_counter[port.process] += 1
    
    # Protocol dağılımı
    protocol_counter = Counter(p['protocol'] for p in ports)
    analysis['by_protocol'] = dict(protocol_counter)
    
    # En çok kullanılan process'ler (top 10)
    analysis['top_processes'] = process_counter.most_common(10)
    
    return analysis


def get_public_ports(ports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Public portları filtreler (bonus fonksiyon).
    
    Args:
        ports: get_listening_ports() çıktısı
    
    Returns:
        List[Dict[str, Any]]: Sadece public portlar
    
    Examples:
        >>> all_ports = get_listening_ports()
        >>> public = get_public_ports(all_ports)
        >>> print(f"{len(public)} public port var")
        >>> for port in public:
        ...     print(f"⚠️  {port['port']} - {port['process']}")
    """
    return [
        p for p in ports
        if p['address'] in ['0.0.0.0', '::', '[::]']
    ]


def get_privileged_ports(ports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Privileged portları filtreler (bonus fonksiyon).
    
    Args:
        ports: get_listening_ports() çıktısı
    
    Returns:
        List[Dict[str, Any]]: Sadece privileged portlar (< 1024)
    
    Examples:
        >>> all_ports = get_listening_ports()
        >>> privileged = get_privileged_ports(all_ports)
        >>> print(f"{len(privileged)} privileged port var")
    """
    return [p for p in ports if p['is_privileged']]


def get_high_risk_ports(ports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Yüksek riskli portları filtreler (bonus fonksiyon).
    
    Args:
        ports: get_listening_ports() çıktısı
    
    Returns:
        List[Dict[str, Any]]: Sadece HIGH risk portlar
    
    Examples:
        >>> all_ports = get_listening_ports()
        >>> high_risk = get_high_risk_ports(all_ports)
        >>> if high_risk:
        ...     print("🔴 Yüksek riskli portlar bulundu!")
        ...     for port in high_risk:
        ...         print(f"  • {port['port']} - {port['process']}")
    """
    result = []
    for port_dict in ports:
        port = PortInfo(**port_dict)
        if port.get_security_risk() == 'HIGH':
            result.append(port_dict)
    return result


# =============================================================================
# MODULE METADATA
# =============================================================================

__all__ = [
    'get_listening_ports',
    'analyze_ports',
    'get_public_ports',
    'get_privileged_ports',
    'get_high_risk_ports',
]