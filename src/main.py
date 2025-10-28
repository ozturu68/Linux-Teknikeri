import argparse
import sys
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich.text import Text

# Tüm analiz modüllerimizi içe aktaralım
from checks.check_system import get_system_info
from checks.check_hardware import get_hardware_info
from checks.check_disk import get_disk_usage
from checks.check_network import get_network_info
from checks.check_services import get_running_services, get_failed_services
from checks.check_drivers import get_missing_pci_drivers, get_gpu_driver_info
from checks.check_storage import check_smart_health
from checks.check_security import get_security_summary, get_listening_ports
from checks.check_performance import get_top_processes

# --- HTML OLUŞTURUCU ---
def generate_html_report(data: dict, filename: str):
    html_style = """
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background-color: #f0f2f5; color: #1c1e21; margin: 0; padding: 20px; }
        .container { max-width: 1000px; margin: auto; background: #fff; border: 1px solid #ddd; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); padding: 20px; }
        h1, h2 { color: #0d6efd; border-bottom: 2px solid #dee2e6; padding-bottom: 10px; }
        h1 { text-align: center; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
        th, td { padding: 12px; border: 1px solid #ddd; text-align: left; word-break: break-word; }
        th { background-color: #f8f9fa; font-weight: bold; }
        .panel { border: 1px solid #ddd; border-radius: 5px; padding: 15px; margin-bottom: 20px; }
        .panel-title { font-weight: bold; margin-top: 0; }
        .panel.good { border-left: 5px solid #198754; background-color: #d1e7dd; }
        .panel.warning { border-left: 5px solid #ffc107; background-color: #fff3cd; }
        .panel.critical { border-left: 5px solid #dc3545; background-color: #f8d7da; }
        footer { text-align: center; margin-top: 20px; font-size: 0.9em; color: #6c757d; }
    </style>
    """
    html_content = f"<!DOCTYPE html><html lang='tr'><head><meta charset='UTF-8'><title>Linux Teknikeri Raporu</title>{html_style}</head><body>"
    html_content += "<div class='container'>"
    html_content += f"<h1>Linux Teknikeri Sistem Analiz Raporu</h1>"
    html_content += f"<p style='text-align:center;'>Oluşturulma Tarihi: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>"

    for key, value in data.items():
        html_content += f"<h2>{key}</h2>"
        if not value: continue
        
        if isinstance(value, list) and value and isinstance(value[0], dict):
            html_content += "<table><thead><tr>"
            for col in value[0].keys(): html_content += f"<th>{col.replace('_', ' ').title()}</th>"
            html_content += "</tr></thead><tbody>"
            for row in value:
                html_content += "<tr>"
                for cell in row.values(): html_content += f"<td>{cell}</td>"
                html_content += "</tr>"
            html_content += "</tbody></table>"
        elif isinstance(value, dict) and 'status' in value:
            status_class = {'İYİ': 'good', 'UYUMLU': 'good', 'GÜVENLİ': 'good', 'MÜKEMMEL': 'good'}.get(value['status'], 'warning')
            if 'KRİTİK' in value.get('title', '') or 'ALARM' in value.get('title', '') or 'SORUNLU' in value.get('status', ''): status_class = 'critical'
            title = value.get('title', 'Durum')
            details = "<br>".join(value.get('details', []))
            html_content += f"<div class='panel {status_class}'><p class='panel-title'>{title}</p><p>{details}</p></div>"
        elif isinstance(value, list):
             html_content += "<ul>" + "".join(f"<li>{item}</li>" for item in value) + "</ul>"
        elif isinstance(value, dict):
            html_content += "<table>"
            for k, v in value.items(): html_content += f"<tr><th>{k.replace('_', ' ').title()}</th><td>{v}</td></tr>"
            html_content += "</table>"
            
    html_content += f"<footer>Rapor, Linux Teknikeri tarafından oluşturulmuştur.</footer></div></body></html>"

    try:
        with open(filename, 'w', encoding='utf-8') as f: f.write(html_content)
        print(f"[bold green]Rapor başarıyla '{filename}' dosyasına kaydedildi.[/bold green]")
    except Exception as e:
        print(f"[bold red]Rapor kaydedilirken bir hata oluştu: {e}[/bold red]")


# --- KONSOL ÇIKTISI OLUŞTURUCULARI (Bu kısım aynı) ---
def display_console_report(console: Console, data: dict):
    # ... (Bu fonksiyonun içeriği önceki adımdakiyle tamamen aynı, değişiklik yok)
    # FAZ 1
    console.print("\n[yellow]--- FAZ 1: ENVANTER RAPORLAMA ---[/yellow]")
    console.print("\n[bold]1. Sistem Envanteri[/bold]"); console.print(create_info_table("Temel Sistem ve Sürüm Bilgileri", data["Sistem Envanteri"]))
    console.print("\n[bold]2. Donanım Envanteri[/bold]"); console.print(create_info_table("Ana Donanım Bileşenleri", data["Donanım Envanteri"]))
    gpu_table = Table(title="[dim]Tespit Edilen Ekran Kartları ve Aktif Sürücüler[/dim]", title_justify="left"); gpu_table.add_column("Ekran Kartı Modeli", style="cyan", overflow="fold"); gpu_table.add_column("Kullanılan Sürücü", style="magenta")
    for gpu in data["Grafik Sürücü (GPU) Denetimi"]: driver_style = "green" if gpu['driver'] not in ["Sürücü Yüklenmemiş", "nouveau"] else "bold red"; styled_driver = Text.from_markup(f"[{driver_style}]{gpu['driver']}[/]"); clean_model = gpu['model'].split(':', 1)[-1].strip().split(' (rev', 1)[0]; gpu_table.add_row(clean_model, styled_driver)
    console.print("\n[bold]2.1 Grafik Sürücü (GPU) Denetimi[/bold]"); console.print(gpu_table)
    disk_table = Table(title="[dim]Fiziksel Disk Bölümleri[/dim]", title_justify="left"); disk_table.add_column("Bölüm", style="cyan"); disk_table.add_column("Bağlama Noktası", style="magenta"); disk_table.add_column("Dosya Sistemi", style="green"); disk_table.add_column("Toplam", justify="right"); disk_table.add_column("Kullanılan", justify="right"); disk_table.add_column("Boş", justify="right"); disk_table.add_column("Kullanım %", justify="right")
    for p in data["Disk Kullanım Alanları"]: disk_table.add_row(p["device"], p["mountpoint"], p["fstype"], p["total"], p["used"], p["free"], p["percent_used"])
    console.print("\n[bold]3. Disk Kullanım Alanları[/bold]"); console.print(disk_table)
    console.print("\n[bold]4. Ağ Bilgileri[/bold]"); console.print(create_info_table("Temel Ağ Yapılandırması", data["Ağ Bilgileri"]))
    if data["Aktif Çalışan Servisler"]: console.print("\n[bold]5. Aktif Çalışan Servisler[/bold]"); console.print(Panel(Columns(sorted(data["Aktif Çalışan Servisler"]), equal=True, expand=True), title="[dim]Çalışan Arka Plan Servisleri[/dim]", border_style="blue"))
    
    # FAZ 2
    console.print("\n[yellow]--- FAZ 2: ANALİZ VE ÖNERİ ---[/yellow]")
    console.print("\n[bold]6. Servis Sağlık Kontrolü[/bold]")
    if data["Servis Sağlık Kontrolü"]: console.print(Panel(Text("\n".join(data["Servis Sağlık Kontrolü"]), style="bold white"), title="[bold red]DİKKAT: Hatalı Servisler Tespit Edildi![/bold red]", subtitle="[red]Bu servisleri 'systemctl status <servis_adı>' komutu ile kontrol edin.[/red]", border_style="red"))
    else: console.print(Panel(Text("Tüm sistem servisleri düzgün çalışıyor.", style="bold green"), title="[bold green]Servis Sağlık Durumu: MÜKEMMEL[/bold green]", border_style="green"))
    console.print("\n[bold]7. Disk Doluluk Analizi[/bold]")
    critical_partitions = [p for p in data["Disk Kullanım Alanları"] if p["percent_used_raw"] > 90.0]
    if critical_partitions: text = "\n".join([f"Bölüm: [bold cyan]{p['mountpoint']}[/] -> Doluluk: [bold red]{p['percent_used_raw']}%[/]" for p in critical_partitions]); console.print(Panel(Text.from_markup(text), title="[bold red]DİKKAT: Disk Doluluk Uyarısı![/bold red]", subtitle="[red]Belirtilen bölümlerde yer açmanız önerilir.[/red]", border_style="red"))
    else: console.print(Panel(Text("Tüm disk bölümlerinin doluluk oranı kritik seviyenin (< 90.0%) altında.", style="bold green"), title="[bold green]Disk Doluluk Durumu: İYİ[/bold green]", border_style="green"))
    console.print("\n[bold]8. PCI Aygıt Sürücü Analizi[/bold]")
    if data["PCI Aygıt Sürücü Analizi"]: console.print(Panel(Text("\n".join(data["PCI Aygıt Sürücü Analizi"]), style="bold white"), title="[bold red]DİKKAT: Sürücüsü Yüklenmemiş Aygıtlar Tespit Edildi![/bold red]", subtitle="[red]Bu aygıtlar için 'linux-firmware' paketini güncellemeyi veya üretici sürücüsü aramayı deneyin.[/red]", border_style="red"))
    else: console.print(Panel(Text("Tüm PCI aygıtları için çekirdek sürücüleri aktif görünüyor.", style="bold green"), title="[bold green]Sürücü Durumu: UYUMLU[/bold green]", border_style="green"))
    console.print("\n[bold]9. Disk Fiziksel Sağlık (S.M.A.R.T.) Analizi[/bold]")
    smart_health = data["Disk Fiziksel Sağlık (S.M.A.R.T.) Analizi"]
    if smart_health['status'] == 'İYİ': console.print(Panel(Text("Tüm diskler S.M.A.R.T. sağlık testini geçti.", style="bold green"), title="[bold green]Disk Sağlığı: İYİ[/bold green]", border_style="green"))
    elif smart_health['status'] == 'SORUNLU': console.print(Panel(Text("\n".join(smart_health['failing_disks']), style="bold white"), title="[bold red]ALARM: KRİTİK DİSK HATASI![/bold red]", subtitle="[red]Verilerinizi DERHAL yedekleyin! Bu disk(ler) fiziksel olarak bozuluyor olabilir.[/red]", border_style="red"))
    else: console.print(Panel(Text("\n".join(smart_health['failing_disks']), style="bold yellow"), title=f"[bold yellow]UYARI: {smart_health['status']}[/bold yellow]", subtitle="[yellow]Disk sağlığı kontrol edilemedi. Detaylar yukarıdadır.[/yellow]", border_style="yellow"))
    console.print("\n[bold]10. Güvenlik Özeti[/bold]")
    security_info = data["Güvenlik Özeti"]; security_findings = []; is_secure = True; updates_count = security_info['security_updates_count']
    if updates_count > 0: security_findings.append(f"[bold red]DİKKAT:[/] {updates_count} adet bekleyen güvenlik güncellemesi var. 'sudo apt upgrade' komutunu çalıştırın."); is_secure = False
    elif updates_count == 0: security_findings.append("[green]Tebrikler:[/] Bekleyen güvenlik güncellemesi bulunmuyor.")
    else: security_findings.append("[yellow]Uyarı:[/] Güvenlik güncellemeleri kontrol edilemedi."); is_secure = False
    fw_status = security_info['firewall_status']
    if fw_status == 'Aktif': security_findings.append("[green]Bilgi:[/] Güvenlik duvarı (ufw) aktif durumda.")
    elif fw_status == 'Devre Dışı': security_findings.append("[bold red]KRİTİK:[/] Güvenlik duvarı (ufw) devre dışı! 'sudo ufw enable' komutuyla etkinleştirin."); is_secure = False
    elif fw_status == 'Kurulu Değil': security_findings.append("[yellow]Öneri:[/] Güvenlik duvarı (ufw) kurulu değil. 'sudo apt install ufw' ile kurabilirsiniz."); is_secure = False
    elif fw_status == "Yetki Gerekli": security_findings.append("[yellow]Uyarı:[/] Güvenlik duvarı durumu için 'sudo' yetkisi gerekiyor."); is_secure = False
    panel_color = "green" if is_secure else "yellow"; panel_title = "[bold green]Güvenlik Durumu: GÜVENLİ[/]" if is_secure else "[bold yellow]Güvenlik Durumu: İYİLEŞTİRME GEREKLİ[/]"; console.print(Panel(Text.from_markup("\n".join(security_findings)), title=panel_title, border_style=panel_color))
    console.print("\n[bold]11. Ağ Dinleme Portları[/bold]")
    listening_ports = data["Ağ Dinleme Portları"]
    if listening_ports and listening_ports[0]['protocol'] == "HATA": console.print(Panel(Text(listening_ports[0]['address'], style="yellow"), title="[yellow]Port Analizi Yapılamadı[/yellow]", border_style="yellow"))
    else:
        port_table = Table(title="[dim]Dış Bağlantıları Dinleyen Aktif Portlar[/dim]", title_justify="left"); port_table.add_column("Protokol", style="white"); port_table.add_column("Adres", style="cyan"); port_table.add_column("Port", style="magenta"); port_table.add_column("Kullanan İşlem", style="green"); has_external_ports = False
        for port_info in listening_ports:
            if port_info["address"] == "0.0.0.0" or port_info["address"] == "[::]": port_table.add_row(port_info["protocol"], port_info["address"], port_info["port"], port_info["process"]); has_external_ports = True
        if has_external_ports: console.print(port_table)
        else: console.print(Panel(Text("Sistemde tüm ağ arayüzlerine açık (0.0.0.0 veya [::]) bir port bulunmuyor.", style="green"), title="[green]Ağ Durumu: GÜVENLİ[/green]", border_style="green"))
    console.print("\n[bold]12. Yüksek Kaynak Tüketen İşlemler[/bold]")
    top_processes = data["Yüksek Kaynak Tüketen İşlemler"]
    if top_processes and top_processes[0]['user'] == 'HATA': console.print(Panel(Text(top_processes[0]['command'], style="yellow"), title="[yellow]Performans Analizi Yapılamadı[/yellow]", border_style="yellow"))
    elif not top_processes: console.print(Panel(Text("Analiz edilecek bir işlem bulunamadı.", style="green"), title="[green]İşlem Durumu[/green]", border_style="green"))
    else:
        process_table = Table(title="[dim]CPU ve Bellek Kullanımına Göre İlk 10 İşlem[/dim]", title_justify="left"); process_table.add_column("Kullanıcı", style="cyan"); process_table.add_column("%CPU", style="magenta", justify="right"); process_table.add_column("%Bellek", style="yellow", justify="right"); process_table.add_column("Komut", style="green", overflow="fold")
        for proc in top_processes: process_table.add_row(proc["user"], proc["cpu"], proc["mem"], proc["command"])
        console.print(process_table)

def create_info_table(title: str, data: dict) -> Table:
    # ... (Bu fonksiyon da aynı, değişiklik yok)
    table = Table(title=f"[dim]{title}[/dim]", title_justify="left")
    table.add_column("Bileşen", justify="right", style="cyan", no_wrap=True)
    table.add_column("Değer", style="magenta")
    for key, value in data.items(): table.add_row(key.replace("_", " ").title(), value)
    return table

# --- YENİ VE GÜNCELLENMİŞ FONKSİYON ---
def transform_data_for_html(data: dict) -> dict:
    """Tüm analiz verilerini HTML oluşturucunun anlayacağı standart bir formata dönüştürür."""
    transformed = data.copy()
    
    # Her bir analiz sonucunu standart bir {'title': ..., 'status': ..., 'details': ...} formatına sokmaya çalışalım.
    # Bu, HTML oluşturucuyu çok daha basit ve güvenilir hale getirir.
    
    # Servis Sağlık
    failed_services = transformed["Servis Sağlık Kontrolü"]
    if failed_services:
        transformed["Servis Sağlık Kontrolü"] = {'title': 'DİKKAT: Hatalı Servisler Tespit Edildi!', 'status': 'UYARI', 'details': failed_services}
    else:
        transformed["Servis Sağlık Kontrolü"] = {'title': 'Servis Sağlık Durumu: MÜKEMMEL', 'status': 'MÜKEMMEL', 'details': ["Tüm sistem servisleri düzgün çalışıyor."]}

    # Disk Doluluk
    critical_partitions = [p for p in transformed["Disk Kullanım Alanları"] if p["percent_used_raw"] > 90.0]
    if critical_partitions:
        details = [f"Bölüm: {p['mountpoint']} -> Doluluk: {p['percent_used']}%" for p in critical_partitions]
        transformed["Disk Doluluk Analizi"] = {'title': 'DİKKAT: Disk Doluluk Uyarısı!', 'status': 'UYARI', 'details': details}
    else:
        transformed["Disk Doluluk Analizi"] = {'title': 'Disk Doluluk Durumu: İYİ', 'status': 'İYİ', 'details': ["Tüm disk bölümlerinin doluluk oranı kritik seviyenin altında."]}

    # PCI Sürücü
    missing_drivers = transformed["PCI Aygıt Sürücü Analizi"]
    if missing_drivers:
        transformed["PCI Aygıt Sürücü Analizi"] = {'title': 'DİKKAT: Sürücüsü Yüklenmemiş Aygıtlar Tespit Edildi!', 'status': 'UYARI', 'details': missing_drivers}
    else:
        transformed["PCI Aygıt Sürücü Analizi"] = {'title': 'Sürücü Durumu: UYUMLU', 'status': 'UYUMLU', 'details': ["Tüm PCI aygıtları için çekirdek sürücüleri aktif görünüyor."]}
        
    # Disk Sağlık (S.M.A.R.T.)
    smart_health = transformed["Disk Fiziksel Sağlık (S.M.A.R.T.) Analizi"]
    smart_status = smart_health['status']
    if smart_status == 'İYİ':
        transformed["Disk Fiziksel Sağlık (S.M.A.R.T.) Analizi"] = {'title': 'Disk Sağlığı: İYİ', 'status': 'İYİ', 'details': ["Tüm diskler S.M.A.R.T. sağlık testini geçti."]}
    else:
        transformed["Disk Fiziksel Sağlık (S.M.A.R.T.) Analizi"] = {'title': f'UYARI: {smart_status}', 'status': smart_status, 'details': smart_health['failing_disks']}

    # Güvenlik Özeti
    security_info = transformed["Güvenlik Özeti"]; security_findings = []; is_secure = True
    updates_count = security_info['security_updates_count']
    if updates_count > 0: security_findings.append(f"DİKKAT: {updates_count} adet bekleyen güvenlik güncellemesi var."); is_secure = False
    elif updates_count == 0: security_findings.append("Tebrikler: Bekleyen güvenlik güncellemesi bulunmuyor.")
    else: security_findings.append("Uyarı: Güvenlik güncellemeleri kontrol edilemedi."); is_secure = False
    fw_status = security_info['firewall_status']
    if fw_status == 'Aktif': security_findings.append("Bilgi: Güvenlik duvarı (ufw) aktif durumda.")
    elif fw_status == 'Devre Dışı': security_findings.append("KRİTİK: Güvenlik duvarı (ufw) devre dışı!"); is_secure = False
    elif fw_status == 'Kurulu Değil': security_findings.append("Öneri: Güvenlik duvarı (ufw) kurulu değil."); is_secure = False
    elif fw_status == "Yetki Gerekli": security_findings.append("Uyarı: Güvenlik duvarı durumu için 'sudo' yetkisi gerekiyor."); is_secure = False
    transformed["Güvenlik Özeti"] = {'title': 'Güvenlik Durumu: GÜVENLİ' if is_secure else 'Güvenlik Durumu: İYİLEŞTİRME GEREKLİ', 'status': 'GÜVENLİ' if is_secure else 'UYARI', 'details': security_findings}
    
    return transformed


# --- ANA FONKSİYON (Bu kısım da aynı) ---
def main():
    parser = argparse.ArgumentParser(description="Kapsamlı bir Linux sistem analizi aracı.")
    parser.add_argument('--html-rapor', type=str, help="Analiz sonuçlarını belirtilen dosyaya HTML formatında aktarır.")
    args = parser.parse_args()

    console = Console()
    console.print("[bold cyan]Linux Teknikeri: Kapsamlı Sistem Analizi[/bold cyan]", justify="center", style="underline")

    with console.status("[bold green]Sistem verileri toplanıyor...[/]") as status:
        all_data = {
            "Sistem Envanteri": get_system_info(),
            "Donanım Envanteri": get_hardware_info(),
            "Grafik Sürücü (GPU) Denetimi": get_gpu_driver_info(),
            "Disk Kullanım Alanları": get_disk_usage(),
            "Ağ Bilgileri": get_network_info(),
            "Aktif Çalışan Servisler": get_running_services(),
            "Servis Sağlık Kontrolü": get_failed_services(),
            "PCI Aygıt Sürücü Analizi": get_missing_pci_drivers(),
            "Disk Fiziksel Sağlık (S.M.A.R.T.) Analizi": check_smart_health(),
            "Güvenlik Özeti": get_security_summary(),
            "Ağ Dinleme Portları": get_listening_ports(),
            "Yüksek Kaynak Tüketen İşlemler": get_top_processes(count=10)
        }
    
    if args.html_rapor:
        console.print(f"[bold yellow]HTML raporu '{args.html_rapor}' dosyasına oluşturuluyor...[/]")
        html_ready_data = transform_data_for_html(all_data.copy()) # Verinin kopyası üzerinde çalışalım
        generate_html_report(html_ready_data, args.html_rapor)
    else:
        display_console_report(console, all_data)

if __name__ == "__main__":
    main()