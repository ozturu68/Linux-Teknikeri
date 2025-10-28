from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns

# Kendi yazdığımız veri toplama modüllerini içe aktarıyoruz.
from checks.check_system import get_system_info
from checks.check_hardware import get_hardware_info
from checks.check_disk import get_disk_usage
from checks.check_network import get_network_info
from checks.check_services import get_running_services

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

    # --- 1. Sistem Envanteri ---
    console.print("\n[yellow]1. Sistem Envanteri toplanıyor...[/yellow]")
    system_data = get_system_info()
    system_table = create_info_table("Sistem Envanteri", system_data)
    console.print(system_table)

    # --- 2. Donanım Envanteri ---
    console.print("\n[yellow]2. Donanım Envanteri toplanıyor...[/yellow]")
    hardware_data = get_hardware_info()
    hardware_table = create_info_table("Donanım Envanteri", hardware_data)
    console.print(hardware_table)

    # --- 3. Disk Kullanım Analizi ---
    console.print("\n[yellow]3. Disk Kullanım Analizi toplanıyor...[/yellow]")
    disk_partitions = get_disk_usage()
    
    disk_table = Table(title="[bold]Disk Kullanım Alanları[/bold]")
    disk_table.add_column("Bölüm", style="cyan")
    disk_table.add_column("Bağlama Noktası", style="magenta")
    disk_table.add_column("Dosya Sistemi", style="green")
    disk_table.add_column("Toplam", justify="right", style="white")
    disk_table.add_column("Kullanılan", justify="right", style="yellow")
    disk_table.add_column("Boş", justify="right", style="green")
    disk_table.add_column("Kullanım %", justify="right", style="bold red")

    for p in disk_partitions:
        disk_table.add_row(
            p["device"], p["mountpoint"], p["fstype"], p["total"],
            p["used"], p["free"], p["percent_used"]
        )
    console.print(disk_table)

    # --- 4. Ağ Analizi ---
    console.print("\n[yellow]4. Ağ Analizi toplanıyor...[/yellow]")
    network_data = get_network_info()
    network_table = create_info_table("Ağ Bilgileri", network_data)
    console.print(network_table)

    # --- 5. Aktif Servisler Analizi ---
    console.print("\n[yellow]5. Aktif Servisler Analizi yapılıyor...[/yellow]")
    running_services = get_running_services()
    
    if running_services:
        # Servis listesini çok sütunlu bir düzende göstermek için Columns kullanıyoruz.
        service_columns = Columns(sorted(running_services), equal=True, expand=True)
        # Bu sütunları daha şık bir görünüm için bir Panel içine yerleştiriyoruz.
        console.print(Panel(
            service_columns, 
            title="[bold]Aktif Çalışan Servisler[/bold]", 
            border_style="green"
        ))
    else:
        console.print("[red]Aktif servisler listelenemedi veya hiç servis çalışmıyor.[/red]")


if __name__ == "__main__":
    main()