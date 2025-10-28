from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich.text import Text

# Kendi yazdığımız veri toplama ve analiz modüllerini içe aktarıyoruz.
# 'src' yapısına göre, bu modüller doğrudan içe aktarılabilir.
from checks.check_system import get_system_info
from checks.check_hardware import get_hardware_info
from checks.check_disk import get_disk_usage
from checks.check_network import get_network_info
from checks.check_services import get_running_services, get_failed_services

def create_info_table(title: str, data: dict) -> Table:
    """
    Verilen başlık ve basit anahtar-değer verisi ile bir rich Table nesnesi oluşturur.
    """
    table = Table(title=f"[bold]{title}[/bold]", title_justify="left")
    table.add_column("Bileşen", justify="right", style="cyan", no_wrap=True)
    table.add_column("Değer", style="magenta")

    for key, value in data.items():
        # Anahtarları daha okunabilir hale getiriyoruz (örn: "Kernel_Version" -> "Kernel Version")
        component_name = key.replace("_", " ").title()
        table.add_row(component_name, value)
    
    return table

def main():
    """
    Ana program fonksiyonu. Sistem analizi yapar ve sonuçları konsola basar.
    """
    console = Console()
    console.print("[bold cyan]Linux Teknikeri: Kapsamlı Sistem Analizi[/bold cyan]", justify="center", style="underline")

    # --- Faz 1: Envanter Raporlama ---
    console.print("\n[yellow]--- FAZ 1: ENVANTER RAPORLAMA ---[/yellow]")
    
    # 1. Geliştirilmiş Sistem Envanteri
    console.print("\n[bold]1. Sistem Envanteri[/bold]")
    system_data = get_system_info()
    console.print(create_info_table("[dim]Temel Sistem ve Sürüm Bilgileri[/dim]", system_data))

    # 2. Donanım Envanteri
    console.print("\n[bold]2. Donanım Envanteri[/bold]")
    hardware_data = get_hardware_info()
    console.print(create_info_table("[dim]Ana Donanım Bileşenleri[/dim]", hardware_data))

    # 3. Disk Kullanım Analizi (Raporlama)
    console.print("\n[bold]3. Disk Kullanım Alanları[/bold]")
    disk_partitions = get_disk_usage()
    disk_table = Table(title="[dim]Fiziksel Disk Bölümleri[/dim]", title_justify="left")
    disk_table.add_column("Bölüm", style="cyan"); disk_table.add_column("Bağlama Noktası", style="magenta"); disk_table.add_column("Dosya Sistemi", style="green"); disk_table.add_column("Toplam", justify="right", style="white"); disk_table.add_column("Kullanılan", justify="right", style="yellow"); disk_table.add_column("Boş", justify="right", style="green"); disk_table.add_column("Kullanım %", justify="right", style="bold red")
    for p in disk_partitions:
        disk_table.add_row(p["device"], p["mountpoint"], p["fstype"], p["total"], p["used"], p["free"], p["percent_used"])
    console.print(disk_table)

    # 4. Ağ Analizi
    console.print("\n[bold]4. Ağ Bilgileri[/bold]")
    network_data = get_network_info()
    console.print(create_info_table("[dim]Temel Ağ Yapılandırması[/dim]", network_data))

    # 5. Aktif Servisler
    console.print("\n[bold]5. Aktif Çalışan Servisler[/bold]")
    running_services = get_running_services()
    if running_services:
        service_columns = Columns(sorted(running_services), equal=True, expand=True)
        console.print(Panel(service_columns, title="[dim]Çalışan Arka Plan Servisleri[/dim]", border_style="blue"))
    
    # --- Faz 2: Analiz ve Öneri ---
    console.print("\n[yellow]--- FAZ 2: ANALİZ VE ÖNERİ ---[/yellow]")

    # 6. Servis Sağlık Kontrolü
    console.print("\n[bold]6. Servis Sağlık Kontrolü[/bold]")
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
            title="[bold green]Servis Sağlık Durumu: MÜKEMMEL[/bold green]",
            border_style="green"
        ))

    # 7. Disk Doluluk Analizi
    console.print("\n[bold]7. Disk Doluluk Analizi[/bold]")
    DISK_USAGE_THRESHOLD = 90.0
    critical_partitions = []
    for p in disk_partitions:
        if p["percent_used_raw"] > DISK_USAGE_THRESHOLD:
            critical_partitions.append(
                f"Bölüm: [bold cyan]{p['mountpoint']}[/] -> Doluluk: [bold red]{p['percent_used_raw']}%[/]"
            )
    
    if critical_partitions:
        critical_text = Text("\n".join(critical_partitions))
        console.print(Panel(
            critical_text,
            title="[bold red]DİKKAT: Disk Doluluk Uyarısı![/bold red]",
            subtitle="[red]Belirtilen bölümlerde yer açmanız önerilir.[/red]",
            border_style="red"
        ))
    else:
        success_text = Text(f"Tüm disk bölümlerinin doluluk oranı kritik seviyenin (< {DISK_USAGE_THRESHOLD}%) altında.", style="bold green")
        console.print(Panel(
            success_text,
            title="[bold green]Disk Doluluk Durumu: İYİ[/bold green]",
            border_style="green"
        ))


if __name__ == "__main__":
    main()