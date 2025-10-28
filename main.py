from rich.console import Console
from rich.table import Table

# Kendi yazdığımız veri toplama fonksiyonunu içe aktarıyoruz.
from checks.check_system import get_system_info

def main():
    """
    Ana program fonksiyonu.
    """
    console = Console()
    console.print("[bold cyan]Linux Teknikeri: Sistem Analizi[/bold cyan]", justify="center")

    # 1. VERİ TOPLAMA
    # Sistem bilgisi toplama fonksiyonumuzu çağırıyoruz.
    console.print("\n[yellow]1. Sistem Envanteri toplanıyor...[/yellow]")
    system_data = get_system_info()

    # 2. RAPORLAMA
    # Toplanan verileri sunmak için bir tablo oluşturuyoruz.
    table = Table(title="[bold green]Sistem Envanteri[/bold green]")

    # Tabloya sütunları ekliyoruz.
    table.add_column("Bileşen", justify="right", style="cyan", no_wrap=True)
    table.add_column("Değer", style="magenta")

    # Topladığımız verileri (sözlük) döngüye alarak tabloya satır olarak ekliyoruz.
    for key, value in system_data.items():
        # Sözlük anahtarını daha okunabilir bir formata çeviriyoruz. (örn: "kernel_version" -> "Kernel Version")
        component_name = key.replace("_", " ").title()
        table.add_row(component_name, value)
    
    # Oluşturulan tabloyu ekrana basıyoruz.
    console.print(table)


if __name__ == "__main__":
    main()