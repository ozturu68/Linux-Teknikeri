import psutil
import socket

def get_network_info():
    """
    Temel ağ bilgilerini (hostname, IP adresi) toplar.
    
    Returns:
        dict: Toplanan ağ bilgilerini içeren bir sözlük.
    """
    info = {}
    
    # 1. Hostname'i al (En kolay ve standart yol)
    try:
        info["hostname"] = socket.gethostname()
    except Exception as e:
        info["hostname"] = f"Alınamadı: {e}"

    # 2. Birincil LAN IP Adresini bul
    lan_ip = "N/A (Bağlantı Yok?)" # Varsayılan değer
    # psutil.net_if_addrs() tüm ağ arayüzlerini ve adreslerini bir sözlük olarak verir.
    all_interfaces = psutil.net_if_addrs()
    
    for interface_name, interface_addresses in all_interfaces.items():
        # 'lo' (localhost) arayüzünü atlıyoruz.
        if "lo" in interface_name.lower():
            continue
            
        for address in interface_addresses:
            # Sadece IPv4 adresleriyle ilgileniyoruz (socket.AF_INET).
            if address.family == socket.AF_INET:
                lan_ip = address.address
                # İlk uygun IP adresini bulduktan sonra döngüden çıkıyoruz.
                break
        # IP bulunduktan sonra dış döngüden de çıkıyoruz.
        if lan_ip != "N/A (Bağlantı Yok?)":
            break
            
    info["lan_ip"] = lan_ip
    
    return info