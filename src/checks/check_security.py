import re
from utils.command_runner import run_command

def _parse_ss_output(output: str) -> list[dict]:
    """'ss -tulnp' komutunun çıktısını ayrıştıran yardımcı fonksiyon."""
    ports = []
    lines = output.strip().split('\n')
    if len(lines) < 2:
        return []

    for line in lines[1:]:
        # ss çıktısı boşluklarla düzensiz olabilir, bu yüzden regex daha güvenilir.
        match = re.match(r'(\w+)\s+\S+\s+\S+\s+([\S]+)\s+([\S]+)\s+(.*)', line)
        if not match:
            continue
        
        protocol, local_address_port, peer_address_port, process_info = match.groups()

        # Adres ve portu ayır
        addr_match = re.search(r'(.+):(\w+)$', local_address_port)
        if not addr_match:
            continue
        address, port = addr_match.groups()

        # Proses bilgisini temizle (daha esnek regex)
        # Örnek: 'users:(("cupsd",pid=1214,fd=7))' -> 'cupsd'
        proc_match = re.search(r'users:\(\("([^"]+)"', process_info)
        process_name = proc_match.group(1) if proc_match else "N/A"
        
        ports.append({
            "protocol": protocol.upper(),
            "address": address,
            "port": port,
            "process": process_name
        })
    return ports

def get_listening_ports():
    """
    Kategori 3: Ağ Dinleme Portları
    `ss -tulnp` komutunu kullanarak dinlemedeki TCP ve UDP portlarını listeler.
    """
    stdout, stderr, retcode = run_command(["sudo", "ss", "-tulnp"])

    if "sudo: a password is required" in stderr:
        return [{"protocol": "HATA", "address": "Yetki Gerekli", "port": "", "process": ""}]
    
    if retcode != 0:
        return [{"protocol": "HATA", "address": "Portlar listelenemedi", "port": "", "process": ""}]

    return _parse_ss_output(stdout)

def get_security_summary():
    """
    Kategori 3: Güvenlik Denetimi
    Bekleyen güvenlik güncellemelerini ve güvenlik duvarı durumunu kontrol eder.
    """
    summary = { "security_updates_count": 0, "firewall_status": "Bilinmiyor" }
    stdout, _, retcode = run_command(["apt", "list", "--upgradable"], suppress_stderr=True)
    if retcode == 0:
        summary["security_updates_count"] = sum(1 for line in stdout.strip().split('\n') if 'security' in line)
    else:
        summary["security_updates_count"] = -1
    
    _, _, ufw_exists_retcode = run_command(["which", "ufw"])
    if ufw_exists_retcode == 0:
        stdout, stderr, retcode = run_command(["sudo", "ufw", "status"])
        if "sudo: a password is required" in stderr:
            summary["firewall_status"] = "Yetki Gerekli"
        elif retcode == 0:
            if "Status: active" in stdout: summary["firewall_status"] = "Aktif"
            elif "Status: inactive" in stdout: summary["firewall_status"] = "Devre Dışı"
    else:
        summary["firewall_status"] = "Kurulu Değil"
        
    return summary