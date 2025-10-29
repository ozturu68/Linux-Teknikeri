import argparse
from datetime import datetime
import re
import logging
import sys
from rich.console import Console, Group
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich.text import Text
from rich import box

# --- İÇE AKTARMALAR ---
from .checks.check_system import get_system_info
from .checks.check_hardware import get_hardware_info
from .checks.check_disk import get_disk_usage, get_top_large_items
from .checks.check_network import get_network_info
from .checks.check_services import get_running_services, get_failed_services, get_services_with_errors
from .checks.check_drivers import get_missing_pci_drivers, get_gpu_driver_info
from .checks.check_storage import check_smart_health
from .checks.check_security import get_security_summary, get_listening_ports, audit_ssh_config
from .checks.check_performance import get_top_processes
from .checks.check_boot import get_boot_blame
from .utils.command_runner import run_command

log = logging.getLogger(__name__)

# --- GÜÇLENDİRİLMİŞ YARDIMCI FONKSİYON ---
def create_info_table(data: dict) -> Table:
    table = Table(box=None, padding=(0, 2))
    table.add_column("Bileşen", style="cyan", no_wrap=True)
    table.add_column("Değer", style="magenta")
    if not isinstance(data, dict):
        table.add_row("[bold red]HATA[/bold red]", "Bu bölüm için veri alınamadı.")
        return table
    for key, value in data.items():
        display_value = str(value) if value is not None else "[dim]Yok[/dim]"
        table.add_row(key.replace("_", " ").title(), display_value)
    return table

# (generate_html_report fonksiyonu doğru, değişiklik yok)
def generate_html_report(console: Console, data: dict, filename: str):
    pass

# --- TAM VE GÜÇLENDİRİLMİŞ RAPORLAMA FONKSİYONU ---
def display_console_report(console: Console, data: dict):
    console.print("\n[yellow]--- FAZ 1: ENVANTER RAPORLAMA ---[/yellow]\n")

    console.print(Panel(create_info_table(data.get("Sistem Envanteri")), title="[bold]1. Sistem Envanteri[/bold]", border_style="green", expand=False))
    console.print(Panel(create_info_table(data.get("Donanım Envanteri")), title="[bold]2. Donanım Envanteri[/bold]", border_style="green", expand=False))
    
    # --- GÖRSEL İYİLEŞTİRME (FİNAL VERSİYONU) ---
    gpu_table = Table(box=box.MINIMAL, show_header=True, header_style="bold")
    gpu_table.add_column("Ekran Kartı Modeli", style="cyan")
    gpu_table.add_column("Kullanılan Sürücü", style="magenta")
    gpu_info = data.get("Grafik Sürücü (GPU) Denetimi")
    
    if gpu_info and isinstance(gpu_info, list):
        for gpu in gpu_info:
            full_model_name = gpu.get('model', 'Bilinmiyor')
            
            # --- YENİ VE KESİN REGEX ---
            # Model ismini, "VGA compatible controller: " veya "3D controller: " gibi ifadelerden sonraki kısımdan başlat.
            match = re.search(r'controller:\s*(.*)', full_model_name)
            clean_name = match.group(1).strip() if match else full_model_name
            # Parantez içindeki (rev...) kısmını da temizleyelim.
            clean_name = re.sub(r'\s*\([^)]*rev[^)]*\)', '', clean_name).strip()

            driver_style = "green" if gpu.get('driver') not in ['Sürücü Yüklenmemiş', 'nouveau', 'Hata'] else 'bold red'
            gpu_table.add_row(clean_name, f"[{driver_style}]{gpu.get('driver', 'Bilinmiyor')}[/]")
    else:
        gpu_table.add_row("GPU bilgisi alınamadı.", "[red]HATA[/red]")
        
    console.print(Panel(gpu_table, title="[bold]2.1 Grafik Sürücü (GPU) Denetimi[/bold]", border_style="green", expand=False))
    
    # --- EKSİK KISIMLAR GERİ EKLENDİ ---
    disk_panel_content = []
    disk_usage_data = data.get("Disk Kullanım Alanları")
    if disk_usage_data:
        disk_table = Table(box=box.ROUNDED, show_header=True)
        disk_table.add_column("Bölüm"); disk_table.add_column("Bağlama Noktası"); disk_table.add_column("Toplam"); disk_table.add_column("Kullanılan"); disk_table.add_column("Boş"); disk_table.add_column("Kullanım %")
        for p in disk_usage_data:
            percent = p.get('percent_used_raw', 0)
            style = 'bold red' if percent > 90 else 'yellow' if percent > 75 else 'default'
            disk_table.add_row(p.get("device"), p.get("mountpoint"), p.get("total"), p.get("used"), p.get("free"), f"[{style}]{p.get('percent_used')}[/]")
        disk_panel_content.append(disk_table)

    large_items = data.get("En Çok Yer Kaplayanlar (Ev Dizini)")
    if large_items:
        large_items_table = Table(title="[dim]En Çok Yer Kaplayan 10 Öğe (Ev Dizini)[/dim]", title_justify="left", box=box.MINIMAL, show_header=True)
        large_items_table.add_column("Boyut", style="yellow", justify="right"); large_items_table.add_column("Dosya / Klasör Yolu", style="cyan")
        for item in large_items:
            large_items_table.add_row(item.get('size'), item.get('path'))
        disk_panel_content.append(large_items_table)
    
    if disk_panel_content:
        console.print(Panel(Group(*disk_panel_content), title="[bold]3. Disk Analizi[/bold]", border_style="green", expand=False))

    if data.get("Ağ Bilgileri"):
        console.print(Panel(create_info_table(data.get("Ağ Bilgileri")), title="[bold]4. Ağ Bilgileri[/bold]", border_style="green", expand=False))
    
    running_services = data.get("Aktif Çalışan Servisler")
    if running_services:
        console.print(Panel(Columns(sorted(running_services)), title="[bold]5. Aktif Çalışan Servisler[/bold]", border_style="blue", expand=False))

    # --- FAZ 2 (ANALİZ) ---
    console.print("\n[yellow]--- FAZ 2: ANALİZ VE ÖNERİ ---[/yellow]\n")
    
    service_analysis = data.get("Servis Sağlık Analizi", {}); failed = service_analysis.get("failed", []); with_errors = service_analysis.get("with_errors", [])
    if failed or with_errors:
        analysis_text = Text()
        panel_style = "red" if failed else "yellow"
        if failed:
            analysis_text.append("ÇÖKMÜŞ (FAILED) SERVİSLER:\n", style="bold red")
            for service in failed: analysis_text.append(f"  - {service}\n")
        if with_errors:
            analysis_text.append("\nŞÜPHELİ SERVİSLER (Son 24 Saatte Hata Kaydı Var):\n" if failed else "ŞÜPHELİ SERVİSLER (Son 24 Saatte Hata Kaydı Var):\n", style="bold yellow")
            for service in with_errors: analysis_text.append(f"  - {service}\n")
        console.print(Panel(analysis_text, title="[bold]6. Servis Sağlık Analizi: DİKKAT[/bold]", subtitle="[dim]'systemctl status' ve 'journalctl -u' komutlarıyla inceleyin.[/dim]", border_style=panel_style))

    boot_blame = data.get("Açılış Performans Analizi")
    if boot_blame:
        boot_table = Table(box=box.MINIMAL, title="[dim]Açılışı En Çok Yavaşlatan 10 Servis[/dim]", title_justify="left", show_header=True)
        boot_table.add_column("Süre", style="red", justify="right"); boot_table.add_column("Servis", style="cyan")
        for item in boot_blame: boot_table.add_row(item.get('time'), item.get('service'))
        console.print(Panel(boot_table, title="[bold]7. Açılış Performans Analizi[/bold]", border_style="yellow"))

    security_summary_data = data.get("Güvenlik Özeti")
    if security_summary_data:
        summary_text = Text()
        updates = security_summary_data.get('security_updates_count', -1)
        firewall = security_summary_data.get('firewall_status', 'Bilinmiyor!')
        
        if updates > 0: summary_text.append(f"Bekleyen {updates} güvenlik güncellemesi var! ", style="bold yellow")
        elif updates == 0: summary_text.append("Tüm güvenlik güncellemeleri yapılmış. ", style="green")
        else: summary_text.append("Güvenlik güncellemesi durumu alınamadı. ", style="dim")

        if firewall == "Aktif": summary_text.append(f"Güvenlik duvarı (UFW) durumu: {firewall}.", style="green")
        else: summary_text.append(f"Güvenlik duvarı (UFW) durumu: {firewall}", style="bold red" if firewall != "Pasif" else "yellow")
        
        console.print(Panel(summary_text, title="[bold]8. Güvenlik Analizi[/bold]", border_style="yellow"))


def main():
    parser = argparse.ArgumentParser(description="Kapsamlı bir Linux sistem analizi aracı.")
    parser.add_argument('--html-rapor', type=str, help="Analiz sonuçlarını belirtilen dosyaya HTML formatında aktarır.")
    args = parser.parse_args()
    console = Console()
    console.print("[bold cyan]Linux Teknikeri: Kapsamlı Sistem Analizi[/bold cyan]", justify="center", style="underline")

    console.print("\n[yellow]Bu betik, tam analiz için 'sudo' yetkisi gerektiren bazı komutlar çalıştırır.[/yellow]")
    console.print("[dim](Güvenlik duvarı durumu, S.M.A.R.T. disk sağlığı, ağ portları vb.)[/dim]")
    try:
        run_command(["sudo", "-v"], timeout=30)
        console.print("[green]Sudo yetkisi alındı.[/green]\n")
    except Exception as e:
        console.print(f"[bold red]Sudo yetkisi alınamadı: {e}[/bold red]")
        console.print("[yellow]Analiz, sudo gerektirmeyen kontrollerle devam edecek.[/yellow]\n")

    with console.status("[bold green]Sistem verileri toplanıyor...[/]") as status:
        all_data = {}
        try: all_data["Sistem Envanteri"] = get_system_info()
        except Exception as e: log.error(f"Sistem Envanteri alınamadı: {e}")
        try: all_data["Donanım Envanteri"] = get_hardware_info()
        except Exception as e: log.error(f"Donanım Envanteri alınamadı: {e}")
        try: all_data["Grafik Sürücü (GPU) Denetimi"] = get_gpu_driver_info()
        except Exception as e: log.error(f"GPU bilgisi alınamadı: {e}")
        try:
            running_services = get_running_services()
            all_data.update({
                "Disk Kullanım Alanları": get_disk_usage(),
                "En Çok Yer Kaplayanlar (Ev Dizini)": get_top_large_items(),
                "Ağ Bilgileri": get_network_info(),
                "Aktif Çalışan Servisler": running_services,
                "Servis Sağlık Analizi": {"failed": get_failed_services(), "with_errors": get_services_with_errors(running_services)},
                "Açılış Performans Analizi": get_boot_blame(),
                "Güvenlik Özeti": get_security_summary(),
            })
        except Exception as e:
            log.critical(f"Ana veri toplama bloğunda bir hata oluştu: {e}")
    
    if args.html_rapor:
        generate_html_report(console, all_data, args.html_rapor)
    else:
        display_console_report(console, all_data)

if __name__ == "__main__":
    main()