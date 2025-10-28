from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich.text import Text

# Kendi yazdığımız veri toplama ve analiz modüllerini içe aktarıyoruz.
from checks.check_system import get_system_info
from checks.check_hardware import get_hardware_info
from checks.check_disk import get_disk_usage
from checks.check_network import get_network_info
from checks.check_services import get_running_services, get_failed_services

def create_info_table(title: str, data: dict) -> Table:
    """
    Verilen başlık ve basit anahtar-değer verisi ile bir rich Table nesnesi oluşturur.
    """
    table = Table(title=f"[bold]{title}[/bold]")
    table.add_column("Bileşen", justify="right", style="cyan", no_wrap=True)
    table.add_column("Değer", style="magenta")

    for key, value in data.items():
        component_name = key.replace("_", " ").title()
        table.add_row(component_name, value)
    
    return table

def main():
    """
    Ana program fonksiyonu.
    """
    console = Console()
    console.print("[bold cyan]Linux Teknikeri: Sistem Analizi[/bold cyan]", justify="center")

    # --- Faz 1: Envanter Raporlama ---
    console.print("\n[yellow]--- FAZ 1: ENVANTER RAPORLAMA ---[/yellow]")
    
    # 1. Sistem Envanteri
    system_data = get_system_info()
    console.print(create_info_table("1. Sistem Envanteri", system_data))

    # 2. Donanım Envanteri
    hardware_data = get_hardware_info()
    console.print(create_info_table("2. Donanım Envanteri", hardware_data))

    # 3. Disk Kullanım Analizi (Raporlama)
    disk_partitions = get_disk_usage()
    disk_table = Table(title="[bold]3. Disk Kullanım Alanları[/bold]")
    disk_table.add_column("Bölüm", style="cyan"); disk_table.add_column("Bağlama Noktası", style="magenta"); disk_table.add_column("Dosya Sistemi", style="green"); disk_table.add_column("Toplam", justify="right", style="white"); disk_table.add_column("Kullanılan", justify="right", style="yellow"); disk_table.add_column("Boş", justify="right", style="green"); disk_table.add_column("Kullanım %", justify="right", style="bold red")
    for p in disk_partitions:
        disk_table.add_row(p["device"], p["mountpoint"], p["fstype"], p["total"], p["used"], p["free"], p["percent_used"])
    console.print(disk_table)

    # 4. Ağ Analizi
    network_data = get_network_info()
    console.print(create_info_table("4. Ağ Bilgileri", network_data))

    # 5. Aktif Servisler
    running_services = get_running_services()
    if running_services:
        service_columns = Columns(sorted(running_services), equal=True, expand=True)
        console.print(Panel(service_columns, title="[bold]5. Aktif Çalışan Servisler[/bold]", border_style="blue"))
    
    # --- Faz 2: Analiz ve Öneri ---
    console.print("\n[yellow]--- FAZ 2: ANALİZ VE ÖNERİ ---[/yellow]")

    # 6. Servis Sağlık Kontrolü
    failed_services = get_failed_services()
    if failed_services:
        failed_text = Text("\n".join(failed_services), style="bold white")
        console.print(Panel(
            failed_text,
            title="[bold red]DİKKAT: Hatalı Servisler Tespit Edildi![/bold red]",
            subtitle="[red]Bu servisleri 'systemctl status <servis_adı>' komutu ile kontrol edin.[/red]",
            border_style="red"
        ))
    else:
        success_text = Text("Tüm sistem servisleri düzgün çalışıyor.", style="bold green")
        console.print(Panel(
            success_text,
            title="[bold green]6. Servis Sağlık Durumu: MÜKEMMEL[/bold green]",
            border_style="green"
        ))

    # 7. Disk Doluluk Analizi
    DISK_USAGE_THRESHOLD = 90.0  # %90 doluluk oranı eşiği
    critical_partitions = []
    for p in disk_partitions:
        if p["percent_used_raw"] > DISK_USAGE_THRESHOLD:
            critical_partitions.append(
                f"Bölüm: [bold cyan]{p['mountpoint']}[/] -> Doluluk: [bold red]{p['percent_used_raw']}%[/]"
            )
    
    if critical_partitions:
        # Doluluk oranı eşiği aşan bölüm(ler) varsa, kırmızı bir uyarı paneli göster.
        critical_text = Text("\n".join(critical_partitions))
        console.print(Panel(
            critical_text,
            title="[bold red]DİKKAT: Disk Doluluk Uyarısı![/bold red]",
            subtitle="[red]Belirtilen bölümlerde yer açmanız önerilir.[/red]",
            border_style="red"
        ))
    else:
        # Kritik seviyede dolu disk yoksa, yeşil bir onay paneli göster.
        success_text = Text(f"Tüm disk bölümlerinin doluluk oranı kritik seviyenin (< {DISK_USAGE_THRESHOLD}%) altında.", style="bold green")
        console.print(Panel(
            success_text,
            title="[bold green]7. Disk Doluluk Durumu: İYİ[/bold green]",
            border_style="green"
        ))


if __name__ == "__main__":
    main()