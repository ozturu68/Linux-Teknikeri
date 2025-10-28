from rich.console import Console
from rich.table import Table

# Kendi yazdığımız veri toplama modüllerini içe aktarıyoruz.
from checks.check_system import get_system_info
from checks.check_hardware import get_hardware_info

def create_info_table(title: str, data: dict) -> Table:
    """
    Verilen başlık ve veri ile bir rich Table nesnesi oluşturur ve doldurur.
    
    Args:
        title (str): Tablonun başlığı.
        data (dict): Tabloya eklenecek anahtar-değer verileri.

    Returns:
        Table: Doldurulmuş ve hazır bir Table nesnesi.
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


if __name__ == "__main__":
    main()