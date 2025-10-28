from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich.text import Text

# Modülleri içe aktar
from checks.check_system import get_system_info
from checks.check_hardware import get_hardware_info
from checks.check_disk import get_disk_usage
from checks.check_network import get_network_info
from checks.check_services import get_running_services, get_failed_services
from checks.check_drivers import get_missing_pci_drivers, get_gpu_driver_info
from checks.check_storage import check_smart_health
from checks.check_security import get_security_summary, get_listening_ports

def create_info_table(title: str, data: dict) -> Table:
    table = Table(title=f"[dim]{title}[/dim]", title_justify="left")
    table.add_column("Bileşen", justify="right", style="cyan", no_wrap=True)
    table.add_column("Değer", style="magenta")
    for key, value in data.items():
        table.add_row(key.replace("_", " ").title(), value)
    return table

def main():
    console = Console()
    console.print("[bold cyan]Linux Teknikeri: Kapsamlı Sistem Analizi[/bold cyan]", justify="center", style="underline")

    # --- FAZ 1: ENVANTER RAPORLAMA ---
    console.print("\n[yellow]--- FAZ 1: ENVANTER RAPORLAMA ---[/yellow]")
    console.print("\n[bold]1. Sistem Envanteri[/bold]")
    console.print(create_info_table("Temel Sistem ve Sürüm Bilgileri", get_system_info()))
    console.print("\n[bold]2. Donanım Envanteri[/bold]")
    console.print(create_info_table("Ana Donanım Bileşenleri", get_hardware_info()))
    console.print("\n[bold]2.1 Grafik Sürücü (GPU) Denetimi[/bold]")
    gpu_data = get_gpu_driver_info()
    gpu_table = Table(title="[dim]Tespit Edilen Ekran Kartları ve Aktif Sürücüler[/dim]", title_justify="left")
    gpu_table.add_column("Ekran Kartı Modeli", style="cyan", overflow="fold")
    gpu_table.add_column("Kullanılan Sürücü", style="magenta")
    for gpu in gpu_data:
        driver_style = "green" if gpu['driver'] not in ["Sürücü Yüklenmemiş", "nouveau"] else "bold red"
        styled_driver = Text.from_markup(f"[{driver_style}]{gpu['driver']}[/]")
        clean_model = gpu['model'].split(':', 1)[-1].strip().split(' (rev', 1)[0]
        gpu_table.add_row(clean_model, styled_driver)
    console.print(gpu_table)
    console.print("\n[bold]3. Disk Kullanım Alanları[/bold]")
    disk_partitions = get_disk_usage()
    disk_table = Table(title="[dim]Fiziksel Disk Bölümleri[/dim]", title_justify="left")
    disk_table.add_column("Bölüm", style="cyan"); disk_table.add_column("Bağlama Noktası", style="magenta"); disk_table.add_column("Dosya Sistemi", style="green"); disk_table.add_column("Toplam", justify="right", style="white"); disk_table.add_column("Kullanılan", justify="right", style="yellow"); disk_table.add_column("Boş", justify="right", style="green"); disk_table.add_column("Kullanım %", justify="right", style="bold red")
    for p in disk_partitions: disk_table.add_row(p["device"], p["mountpoint"], p["fstype"], p["total"], p["used"], p["free"], p["percent_used"])
    console.print(disk_table)
    console.print("\n[bold]4. Ağ Bilgileri[/bold]")
    console.print(create_info_table("Temel Ağ Yapılandırması", get_network_info()))
    console.print("\n[bold]5. Aktif Çalışan Servisler[/bold]")
    running_services = get_running_services()
    if running_services: console.print(Panel(Columns(sorted(running_services), equal=True, expand=True), title="[dim]Çalışan Arka Plan Servisleri[/dim]", border_style="blue"))
    
    # --- FAZ 2: ANALİZ VE ÖNERİ ---
    console.print("\n[yellow]--- FAZ 2: ANALİZ VE ÖNERİ ---[/yellow]")
    console.print("\n[bold]6. Servis Sağlık Kontrolü[/bold]")
    failed_services = get_failed_services()
    if failed_services: console.print(Panel(Text("\n".join(failed_services), style="bold white"), title="[bold red]DİKKAT: Hatalı Servisler Tespit Edildi![/bold red]", subtitle="[red]Bu servisleri 'systemctl status <servis_adı>' komutu ile kontrol edin.[/red]", border_style="red"))
    else: console.print(Panel(Text("Tüm sistem servisleri düzgün çalışıyor.", style="bold green"), title="[bold green]Servis Sağlık Durumu: MÜKEMMEL[/bold green]", border_style="green"))
    console.print("\n[bold]7. Disk Doluluk Analizi[/bold]")
    DISK_USAGE_THRESHOLD = 90.0; critical_partitions = [p for p in disk_partitions if p["percent_used_raw"] > DISK_USAGE_THRESHOLD]
    if critical_partitions: text = "\n".join([f"Bölüm: [bold cyan]{p['mountpoint']}[/] -> Doluluk: [bold red]{p['percent_used_raw']}%[/]" for p in critical_partitions]); console.print(Panel(Text.from_markup(text), title="[bold red]DİKKAT: Disk Doluluk Uyarısı![/bold red]", subtitle="[red]Belirtilen bölümlerde yer açmanız önerilir.[/red]", border_style="red"))
    else: console.print(Panel(Text(f"Tüm disk bölümlerinin doluluk oranı kritik seviyenin (< {DISK_USAGE_THRESHOLD}%) altında.", style="bold green"), title="[bold green]Disk Doluluk Durumu: İYİ[/bold green]", border_style="green"))
    console.print("\n[bold]8. PCI Aygıt Sürücü Analizi[/bold]")
    missing_driver_devices = get_missing_pci_drivers()
    if missing_driver_devices: console.print(Panel(Text("\n".join(missing_driver_devices), style="bold white"), title="[bold red]DİKKAT: Sürücüsü Yüklenmemiş Aygıtlar Tespit Edildi![/bold red]", subtitle="[red]Bu aygıtlar için 'linux-firmware' paketini güncellemeyi veya üretici sürücüsü aramayı deneyin.[/red]", border_style="red"))
    else: console.print(Panel(Text("Tüm PCI aygıtları için çekirdek sürücüleri aktif görünüyor.", style="bold green"), title="[bold green]Sürücü Durumu: UYUMLU[/bold green]", border_style="green"))
    console.print("\n[bold]9. Disk Fiziksel Sağlık (S.M.A.R.T.) Analizi[/bold]")
    smart_health = check_smart_health()
    if smart_health['status'] == 'İYİ': console.print(Panel(Text("Tüm diskler S.M.A.R.T. sağlık testini geçti.", style="bold green"), title="[bold green]Disk Sağlığı: İYİ[/bold green]", border_style="green"))
    elif smart_health['status'] == 'SORUNLU': console.print(Panel(Text("\n".join(smart_health['failing_disks']), style="bold white"), title="[bold red]ALARM: KRİTİK DİSK HATASI![/bold red]", subtitle="[red]Verilerinizi DERHAL yedekleyin! Bu disk(ler) fiziksel olarak bozuluyor olabilir.[/red]", border_style="red"))
    else: console.print(Panel(Text("\n".join(smart_health['failing_disks']), style="bold yellow"), title=f"[bold yellow]UYARI: {smart_health['status']}[/bold yellow]", subtitle="[yellow]Disk sağlığı kontrol edilemedi. Detaylar yukarıdadır.[/yellow]", border_style="yellow"))
    
    console.print("\n[bold]10. Güvenlik Özeti[/bold]")
    security_info = get_security_summary(); security_findings = []; is_secure = True
    updates_count = security_info['security_updates_count']
    if updates_count > 0: security_findings.append(f"[bold red]DİKKAT:[/] {updates_count} adet bekleyen güvenlik güncellemesi var. 'sudo apt upgrade' komutunu çalıştırın."); is_secure = False
    elif updates_count == 0: security_findings.append("[green]Tebrikler:[/] Bekleyen güvenlik güncellemesi bulunmuyor.")
    else: security_findings.append("[yellow]Uyarı:[/] Güvenlik güncellemeleri kontrol edilemedi."); is_secure = False
    fw_status = security_info['firewall_status']
    if fw_status == 'Aktif': security_findings.append("[green]Bilgi:[/] Güvenlik duvarı (ufw) aktif durumda.")
    elif fw_status == 'Devre Dışı': security_findings.append("[bold red]KRİTİK:[/] Güvenlik duvarı (ufw) devre dışı! 'sudo ufw enable' komutuyla etkinleştirin."); is_secure = False
    elif fw_status == 'Kurulu Değil': security_findings.append("[yellow]Öneri:[/] Güvenlik duvarı (ufw) kurulu değil. 'sudo apt install ufw' ile kurabilirsiniz."); is_secure = False
    elif fw_status == "Yetki Gerekli": security_findings.append("[yellow]Uyarı:[/] Güvenlik duvarı durumu için 'sudo' yetkisi gerekiyor."); is_secure = False
    panel_color = "green" if is_secure else "yellow"; panel_title = "[bold green]Güvenlik Durumu: GÜVENLİ[/]" if is_secure else "[bold yellow]Güvenlik Durumu: İYİLEŞTİRME GEREKLİ[/]"; console.print(Panel(Text.from_markup("\n".join(security_findings)), title=panel_title, border_style=panel_color))

    # GÜNCELLENMİŞ BÖLÜM
    console.print("\n[bold]11. Ağ Dinleme Portları[/bold]")
    listening_ports = get_listening_ports()
    if listening_ports and listening_ports[0]['protocol'] == "HATA":
        console.print(Panel(Text(listening_ports[0]['address'], style="yellow"), title="[yellow]Port Analizi Yapılamadı[/yellow]", border_style="yellow"))
    else:
        port_table = Table(title="[dim]Dış Bağlantıları Dinleyen Aktif Portlar[/dim]", title_justify="left")
        port_table.add_column("Protokol", style="white")
        port_table.add_column("Adres", style="cyan")
        port_table.add_column("Port", style="magenta")
        port_table.add_column("Kullanan İşlem", style="green")
        
        has_external_ports = False
        # Gelişmiş filtreleme: Sadece '0.0.0.0' ve '[::]' (tüm adresler) dışarıya açık kabul edilir.
        for port_info in listening_ports:
            if port_info["address"] == "0.0.0.0" or port_info["address"] == "[::]":
                port_table.add_row(
                    port_info["protocol"],
                    port_info["address"],
                    port_info["port"],
                    port_info["process"]
                )
                has_external_ports = True
        
        if has_external_ports:
            console.print(port_table)
        else:
            console.print(Panel(Text("Sistemde tüm ağ arayüzlerine açık (0.0.0.0 veya [::]) bir port bulunmuyor.", style="green"), title="[green]Ağ Durumu: GÜVENLİ[/green]", border_style="green"))

if __name__ == "__main__":
    main()