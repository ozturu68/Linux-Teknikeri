"""
Linux Teknikeri - Ana Program Modülü
Kapsamlı sistem analizi ve raporlama aracı.
"""
import argparse
from datetime import datetime
import re
import logging
import sys
from typing import Dict, List, Tuple
from rich.console import Console, Group
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich.text import Text
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn

# --- İÇE AKTARMALAR ---
from .checks.check_system import get_system_info
from .checks.check_hardware import get_hardware_info
from .checks.check_disk import get_disk_usage, get_top_large_items
from .checks.check_network import get_network_info
from .checks.check_services import get_running_services, get_failed_services, get_services_with_errors
from .checks.check_drivers import get_missing_pci_drivers, get_gpu_driver_info
from .checks.check_storage import check_smart_health
from .checks.check_security import (
    get_security_summary, 
    get_listening_ports, 
    audit_ssh_config,
    check_failed_login_attempts
)
from .checks.check_performance import get_top_processes
from .checks.check_boot import get_boot_blame
from .utils.command_runner import run_command

log = logging.getLogger(__name__)

# =============================================================================
# YARDIMCI FONKSİYONLAR
# =============================================================================

def create_info_table(data: dict) -> Table:
    """Sözlük verilerini tablo formatına dönüştürür."""
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


def clean_gpu_model_name(full_model_name: str) -> str:
    """GPU model ismini temizler, gereksiz ön ekler ve sürüm bilgilerini kaldırır."""
    # "VGA compatible controller: " veya "3D controller: " kısmını kaldır
    match = re.search(r'controller:\s*(.*)', full_model_name, re.IGNORECASE)
    clean_name = match.group(1).strip() if match else full_model_name
    
    # Parantez içindeki (rev XX) kısımlarını temizle
    clean_name = re.sub(r'\s*\([^)]*rev[^)]*\)', '', clean_name).strip()
    
    return clean_name


def calculate_health_score(data: Dict) -> Tuple[int, Dict[str, any]]:
    """
    Sistem sağlık skoru hesaplar (0-100).
    
    Puanlama:
    - Disk Sağlığı: 30 puan
    - Servis Durumu: 25 puan
    - Güvenlik: 25 puan
    - Performans: 20 puan
    
    Returns:
        Tuple[int, Dict]: (toplam_skor, detaylı_skorlar)
    """
    scores = {
        "disk": 30,
        "services": 25,
        "security": 25,
        "performance": 20,
        "details": {}
    }
    
    total_score = 0
    
    # 1. Disk Sağlığı (30 puan)
    disk_score = 30
    disk_usage = data.get("Disk Kullanım Alanları", [])
    smart_health = data.get("S.M.A.R.T. Disk Sağlığı", {})
    
    # Disk doluluk oranı kontrolü
    for disk in disk_usage:
        percent = disk.get('percent_used_raw', 0)
        if percent > 95:
            disk_score -= 10
        elif percent > 85:
            disk_score -= 5
    
    # S.M.A.R.T. kontrolü
    if smart_health.get('status') == 'SORUNLU':
        disk_score -= 20
    elif smart_health.get('status') in ['KONTROL EDİLEMEDİ', 'BİLGİ YOK']:
        disk_score -= 5
    
    scores["details"]["disk"] = max(0, disk_score)
    total_score += scores["details"]["disk"]
    
    # 2. Servis Durumu (25 puan)
    service_score = 25
    service_analysis = data.get("Servis Sağlık Analizi", {})
    failed = service_analysis.get("failed", [])
    with_errors = service_analysis.get("with_errors", [])
    
    service_score -= len(failed) * 10  # Her çökmüş servis 10 puan düşürür
    service_score -= len(with_errors) * 2  # Her şüpheli servis 2 puan düşürür
    
    scores["details"]["services"] = max(0, service_score)
    total_score += scores["details"]["services"]
    
    # 3. Güvenlik (25 puan)
    security_score = 25
    security_summary = data.get("Güvenlik Özeti", {})
    
    # Güvenlik güncellemeleri
    updates = security_summary.get('security_updates_count', 0)
    if updates > 10:
        security_score -= 10
    elif updates > 5:
        security_score -= 5
    elif updates > 0:
        security_score -= 2
    
    # Güvenlik duvarı
    firewall = security_summary.get('firewall_status', '')
    if firewall not in ['Aktif']:
        security_score -= 10
    
    scores["details"]["security"] = max(0, security_score)
    total_score += scores["details"]["security"]
    
    # 4. Performans (20 puan)
    performance_score = 20
    boot_blame = data.get("Açılış Performans Analizi", [])
    
    # Yavaş başlangıç servisleri
    if boot_blame and isinstance(boot_blame, list):
        for item in boot_blame[:3]:  # İlk 3 servis
            time_str = item.get('time', '0s')
            if time_str.endswith('s'):
                try:
                    seconds = float(time_str[:-1])
                    if seconds > 10:
                        performance_score -= 5
                    elif seconds > 5:
                        performance_score -= 2
                except ValueError:
                    pass
    
    scores["details"]["performance"] = max(0, performance_score)
    total_score += scores["details"]["performance"]
    
    return total_score, scores["details"]


def get_health_status_emoji(score: int) -> str:
    """Skor için emoji döndürür."""
    if score >= 90:
        return "🟢"  # Mükemmel
    elif score >= 75:
        return "🟡"  # İyi
    elif score >= 50:
        return "🟠"  # Orta
    else:
        return "🔴"  # Kötü


def format_boot_time_with_color(time_str: str) -> Tuple[str, str]:
    """
    Boot süresi için renk kodu döndürür.
    
    Returns:
        Tuple[str, str]: (time_str, color_style)
    """
    if time_str.endswith('s'):
        try:
            seconds = float(time_str[:-1])
            if seconds > 10:
                return time_str, "bold red"
            elif seconds > 5:
                return time_str, "yellow"
            elif seconds > 2:
                return time_str, "default"
            else:
                return time_str, "green"
        except ValueError:
            pass
    return time_str, "default"


# =============================================================================
# HTML RAPOR OLUŞTURUCU
# =============================================================================

def generate_html_report(console: Console, data: dict, filename: str):
    """Toplanan verileri HTML formatında rapor olarak kaydeder."""
    
    # Sistem sağlık skoru hesapla
    health_score, score_details = calculate_health_score(data)
    
    html_style = """
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; 
            background-color: #f5f5f5; 
            color: #333; 
            margin: 0; 
            padding: 20px; 
            line-height: 1.6;
        }
        .container { 
            max-width: 1200px; 
            margin: 0 auto; 
            background: #fff; 
            border-radius: 10px; 
            box-shadow: 0 2px 10px rgba(0,0,0,0.1); 
            padding: 30px; 
        }
        h1 { 
            color: #2c3e50; 
            text-align: center; 
            border-bottom: 3px solid #3498db; 
            padding-bottom: 15px; 
            margin-bottom: 30px;
        }
        h2 { 
            color: #3498db; 
            border-bottom: 2px solid #ecf0f1; 
            padding-bottom: 10px; 
            margin-top: 30px;
        }
        h3 {
            color: #34495e;
            margin-top: 20px;
        }
        table { 
            width: 100%; 
            border-collapse: collapse; 
            margin: 20px 0; 
            background: #fff;
        }
        th, td { 
            padding: 12px; 
            border: 1px solid #ddd; 
            text-align: left; 
        }
        th { 
            background-color: #3498db; 
            color: white; 
            font-weight: bold; 
        }
        tr:nth-child(even) { 
            background-color: #f9f9f9; 
        }
        .panel { 
            border: 1px solid #ddd; 
            border-radius: 5px; 
            padding: 15px; 
            margin: 15px 0; 
            background: #fafafa;
        }
        .panel.success { 
            border-left: 5px solid #27ae60; 
            background-color: #e8f8f5; 
        }
        .panel.warning { 
            border-left: 5px solid #f39c12; 
            background-color: #fef5e7; 
        }
        .panel.danger { 
            border-left: 5px solid #e74c3c; 
            background-color: #fadbd8; 
        }
        .panel.info { 
            border-left: 5px solid #3498db; 
            background-color: #ebf5fb; 
        }
        .score-container {
            text-align: center;
            padding: 30px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 10px;
            color: white;
            margin: 20px 0;
        }
        .score-value {
            font-size: 72px;
            font-weight: bold;
            margin: 10px 0;
        }
        .score-breakdown {
            display: flex;
            justify-content: space-around;
            margin-top: 20px;
            flex-wrap: wrap;
        }
        .score-item {
            text-align: center;
            padding: 10px;
            min-width: 150px;
        }
        footer { 
            text-align: center; 
            margin-top: 40px; 
            padding-top: 20px; 
            border-top: 1px solid #ddd; 
            color: #7f8c8d; 
            font-size: 0.9em; 
        }
        .badge { 
            display: inline-block; 
            padding: 4px 8px; 
            border-radius: 3px; 
            font-size: 0.85em; 
            font-weight: bold;
        }
        .badge-success { background-color: #27ae60; color: white; }
        .badge-warning { background-color: #f39c12; color: white; }
        .badge-danger { background-color: #e74c3c; color: white; }
        .badge-info { background-color: #3498db; color: white; }
        .recommendation {
            background-color: #e8f4f8;
            border-left: 4px solid #3498db;
            padding: 10px;
            margin: 10px 0;
        }
        code {
            background-color: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }
    </style>
    """
    
    html_content = f"""<!DOCTYPE html>
<html lang='tr'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>Linux Teknikeri - Sistem Analiz Raporu</title>
    {html_style}
</head>
<body>
<div class='container'>
    <h1>🐧 Linux Teknikeri Sistem Analiz Raporu</h1>
    <p style='text-align:center; color:#7f8c8d;'>
        <strong>Oluşturulma Tarihi:</strong> {datetime.now().strftime('%d %B %Y, %H:%M:%S')}
    </p>
    
    <!-- Sistem Sağlık Skoru -->
    <div class='score-container'>
        <h2 style='color:white; border:none; margin:0;'>Sistem Sağlık Skoru</h2>
        <div class='score-value'>{health_score}/100</div>
        <p style='font-size:20px; margin:5px;'>{get_health_status_emoji(health_score)} {
            "Mükemmel" if health_score >= 90 else
            "İyi" if health_score >= 75 else
            "Orta" if health_score >= 50 else
            "Kötü"
        }</p>
        
        <div class='score-breakdown'>
            <div class='score-item'>
                <div style='font-size:24px; font-weight:bold;'>{score_details.get('disk', 0)}/30</div>
                <div>Disk Sağlığı</div>
            </div>
            <div class='score-item'>
                <div style='font-size:24px; font-weight:bold;'>{score_details.get('services', 0)}/25</div>
                <div>Servisler</div>
            </div>
            <div class='score-item'>
                <div style='font-size:24px; font-weight:bold;'>{score_details.get('security', 0)}/25</div>
                <div>Güvenlik</div>
            </div>
            <div class='score-item'>
                <div style='font-size:24px; font-weight:bold;'>{score_details.get('performance', 0)}/20</div>
                <div>Performans</div>
            </div>
        </div>
    </div>
"""
    
    # Sistem Bilgileri
    if data.get("Sistem Envanteri"):
        html_content += "<h2>📋 Sistem Envanteri</h2><table>"
        html_content += "<tr><th>Özellik</th><th>Değer</th></tr>"
        for key, value in data["Sistem Envanteri"].items():
            html_content += f"<tr><td>{key.replace('_', ' ').title()}</td><td>{value}</td></tr>"
        html_content += "</table>"
    
    # Donanım Bilgileri
    if data.get("Donanım Envanteri"):
        html_content += "<h2>💻 Donanım Envanteri</h2><table>"
        html_content += "<tr><th>Bileşen</th><th>Model/Bilgi</th></tr>"
        for key, value in data["Donanım Envanteri"].items():
            html_content += f"<tr><td>{key.replace('_', ' ').title()}</td><td>{value}</td></tr>"
        html_content += "</table>"
    
    # GPU Bilgileri
    if data.get("Grafik Sürücü (GPU) Denetimi"):
        html_content += "<h2>🎮 Grafik Kartı ve Sürücüler</h2><table>"
        html_content += "<tr><th>Model</th><th>Sürücü</th></tr>"
        for gpu in data["Grafik Sürücü (GPU) Denetimi"]:
            model = clean_gpu_model_name(gpu.get('model', 'Bilinmiyor'))
            driver = gpu.get('driver', 'Bilinmiyor')
            driver_badge = "badge-success" if driver not in ['Sürücü Yüklenmemiş', 'nouveau'] else "badge-danger"
            html_content += f"<tr><td>{model}</td><td><span class='badge {driver_badge}'>{driver}</span></td></tr>"
        html_content += "</table>"
    
    # Disk Kullanımı
    if data.get("Disk Kullanım Alanları"):
        html_content += "<h2>💾 Disk Kullanım Alanları</h2><table>"
        html_content += "<tr><th>Bölüm</th><th>Bağlama Noktası</th><th>Toplam</th><th>Kullanılan</th><th>Boş</th><th>Doluluk</th></tr>"
        for disk in data["Disk Kullanım Alanları"]:
            percent = disk.get('percent_used_raw', 0)
            badge = "badge-danger" if percent > 90 else "badge-warning" if percent > 75 else "badge-success"
            html_content += f"""<tr>
                <td>{disk.get('device')}</td>
                <td>{disk.get('mountpoint')}</td>
                <td>{disk.get('total')}</td>
                <td>{disk.get('used')}</td>
                <td>{disk.get('free')}</td>
                <td><span class='badge {badge}'>{disk.get('percent_used')}</span></td>
            </tr>"""
        html_content += "</table>"
    
    # S.M.A.R.T. Disk Detayları
    if data.get("S.M.A.R.T. Disk Sağlığı"):
        smart = data["S.M.A.R.T. Disk Sağlığı"]
        disk_details = smart.get('disk_details', [])
        
        if disk_details:
            html_content += "<h2>🩺 Disk Fiziksel Sağlık (S.M.A.R.T.) - Detaylar</h2>"
            for disk in disk_details:
                status_badge = "badge-success" if disk.get('health_status') in ['PASSED', 'OK'] else "badge-danger"
                html_content += f"<h3>{disk.get('device')} - {disk.get('model', 'N/A')}</h3>"
                html_content += "<table>"
                html_content += f"<tr><td>Durum</td><td><span class='badge {status_badge}'>{disk.get('health_status')}</span></td></tr>"
                html_content += f"<tr><td>Sıcaklık</td><td>{disk.get('temperature')}</td></tr>"
                html_content += f"<tr><td>Çalışma Saati</td><td>{disk.get('power_on_hours')}</td></tr>"
                html_content += f"<tr><td>Açma-Kapama Döngüsü</td><td>{disk.get('power_cycle_count')}</td></tr>"
                html_content += f"<tr><td>Yeniden Tahsis Edilmiş Sektörler</td><td>{disk.get('reallocated_sectors')}</td></tr>"
                if disk.get('wear_leveling') != 'N/A':
                    html_content += f"<tr><td>SSD Ömrü (Wear Leveling)</td><td>{disk.get('wear_leveling')}</td></tr>"
                html_content += "</table>"
                
                if disk.get('warnings'):
                    html_content += "<div class='recommendation'>"
                    html_content += "<strong>⚠️ Uyarılar:</strong><ul>"
                    for warning in disk['warnings']:
                        html_content += f"<li>{warning}</li>"
                    html_content += "</ul></div>"
    
    # Servis Analizi
    if data.get("Servis Sağlık Analizi"):
        failed = data["Servis Sağlık Analizi"].get("failed", [])
        with_errors = data["Servis Sağlık Analizi"].get("with_errors", [])
        
        if failed or with_errors:
            panel_class = "danger" if failed else "warning"
            html_content += f"<div class='panel {panel_class}'>"
            html_content += "<h3>⚠️ Servis Sağlık Analizi</h3>"
            
            if failed:
                html_content += "<h4>Çökmüş Servisler:</h4><ul>"
                for service in failed:
                    html_content += f"<li><strong>{service}</strong></li>"
                html_content += "</ul>"
                html_content += "<div class='recommendation'>"
                html_content += f"<strong>💡 Düzeltme:</strong> <code>sudo systemctl restart {failed[0] if failed else 'servis-adi'}</code>"
                html_content += "</div>"
            
            if with_errors:
                html_content += "<h4>Şüpheli Servisler (Son 24 Saatte Hata):</h4><ul>"
                for service in with_errors:
                    html_content += f"<li>{service}</li>"
                html_content += "</ul>"
                html_content += "<div class='recommendation'>"
                html_content += f"<strong>💡 İnceleme:</strong> <code>sudo journalctl -u {with_errors[0] if with_errors else 'servis-adi'} -n 50</code>"
                html_content += "</div>"
            
            html_content += "</div>"
    
    # Güvenlik Özeti
    if data.get("Güvenlik Özeti"):
        security = data["Güvenlik Özeti"]
        updates = security.get('security_updates_count', -1)
        firewall = security.get('firewall_status', 'Bilinmiyor')
        
        panel_class = "danger" if updates > 5 or firewall != "Aktif" else "success"
        html_content += f"<div class='panel {panel_class}'>"
        html_content += "<h3>🔒 Güvenlik Özeti</h3>"
        html_content += f"<p><strong>Bekleyen Güvenlik Güncellemeleri:</strong> {updates if updates >= 0 else 'Tespit Edilemedi'}</p>"
        html_content += f"<p><strong>Güvenlik Duvarı (UFW):</strong> {firewall}</p>"
        
        if updates > 0:
            html_content += "<div class='recommendation'>"
            html_content += "<strong>💡 Güncelleme:</strong> <code>sudo apt update && sudo apt upgrade</code>"
            html_content += "</div>"
        
        if firewall != "Aktif":
            html_content += "<div class='recommendation'>"
            html_content += "<strong>💡 Güvenlik Duvarını Aktifleştir:</strong> <code>sudo ufw enable</code>"
            html_content += "</div>"
        
        html_content += "</div>"
    
    # SSH Güvenlik Denetimi
    if data.get("SSH Güvenlik Denetimi"):
        ssh_findings = data["SSH Güvenlik Denetimi"]
        critical_findings = [f for f in ssh_findings if f.get('level') == 'KRİTİK']
        
        if critical_findings:
            html_content += "<div class='panel danger'>"
            html_content += "<h3>🔐 SSH Güvenlik Denetimi - KRİTİK SORUNLAR</h3>"
            for finding in critical_findings:
                html_content += f"<p><strong>{finding.get('finding')}</strong></p>"
                html_content += f"<div class='recommendation'><strong>💡 Öneri:</strong> {finding.get('recommendation')}</div>"
            html_content += "</div>"
    
    # Failed Login Attempts
    if data.get("Başarısız Giriş Denemeleri"):
        failed_logins = data["Başarısız Giriş Denemeleri"]
        total = failed_logins.get('total', 0)
        
        if total > 10:
            html_content += "<div class='panel warning'>"
            html_content += f"<h3>🚨 Başarısız Giriş Denemeleri: {total}</h3>"
            
            recent_attacks = failed_logins.get('recent_attacks', [])
            if recent_attacks:
                html_content += "<table><tr><th>IP Adresi</th><th>Deneme Sayısı</th></tr>"
                for attack in recent_attacks[:5]:
                    html_content += f"<tr><td>{attack.get('ip')}</td><td>{attack.get('attempts')}</td></tr>"
                html_content += "</table>"
            
            html_content += "<div class='recommendation'>"
            html_content += "<strong>💡 Öneri:</strong> Şüpheli IP'leri engelleyin: <code>sudo ufw deny from IP_ADRESI</code>"
            html_content += "</div>"
            html_content += "</div>"
    
    # Footer
    html_content += f"""
    <footer>
        <p><strong>Linux Teknikeri</strong> v0.3.0 - Sistem Analiz Aracı</p>
        <p>© {datetime.now().year} | Açık Kaynak Proje - <a href="https://github.com/ozturu68/Linux-Teknikeri">GitHub</a></p>
    </footer>
</div>
</body>
</html>
"""
    
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        console.print(f"\n[green]✓[/green] HTML rapor başarıyla oluşturuldu: [cyan]{filename}[/cyan]")
        console.print(f"[dim]Dosya boyutu: {len(html_content) // 1024} KB[/dim]")
    except Exception as e:
        console.print(f"[bold red]✗[/bold red] HTML rapor oluşturulamadı: {e}")
        log.error(f"HTML rapor hatası: {e}")


# =============================================================================
# KONSOL RAPOR GÖRÜNTÜLEME
# =============================================================================

def display_console_report(console: Console, data: dict):
    """Toplanan verileri terminalde zengin formatta görüntüler."""
    
    console.print("\n[yellow]━━━ FAZ 1: ENVANTER RAPORLAMA ━━━[/yellow]\n")

    # 1. Sistem Envanteri
    console.print(Panel(
        create_info_table(data.get("Sistem Envanteri", {})), 
        title="[bold]1. Sistem Envanteri[/bold]", 
        border_style="green", 
        expand=False
    ))
    
    # 2. Donanım Envanteri
    console.print(Panel(
        create_info_table(data.get("Donanım Envanteri", {})), 
        title="[bold]2. Donanım Envanteri[/bold]", 
        border_style="green", 
        expand=False
    ))
    
    # 2.1 GPU Sürücü Bilgileri
    gpu_table = Table(box=box.MINIMAL, show_header=True, header_style="bold cyan")
    gpu_table.add_column("Ekran Kartı Modeli", style="cyan")
    gpu_table.add_column("Kullanılan Sürücü", style="magenta")
    
    gpu_info = data.get("Grafik Sürücü (GPU) Denetimi", [])
    if gpu_info and isinstance(gpu_info, list):
        for gpu in gpu_info:
            full_model_name = gpu.get('model', 'Bilinmiyor')
            clean_name = clean_gpu_model_name(full_model_name)
            
            driver = gpu.get('driver', 'Bilinmiyor')
            driver_style = "green" if driver not in ['Sürücü Yüklenmemiş', 'nouveau', 'Hata'] else 'bold red'
            gpu_table.add_row(clean_name, f"[{driver_style}]{driver}[/]")
    else:
        gpu_table.add_row("GPU bilgisi alınamadı.", "[red]HATA[/red]")
    
    console.print(Panel(
        gpu_table, 
        title="[bold]2.1 Grafik Sürücü (GPU) Denetimi[/bold]", 
        border_style="green", 
        expand=False
    ))
    
    # 3. Disk Analizi
    disk_panel_content = []
    disk_usage_data = data.get("Disk Kullanım Alanları")
    
    if disk_usage_data:
        disk_table = Table(box=box.ROUNDED, show_header=True)
        disk_table.add_column("Bölüm", style="cyan")
        disk_table.add_column("Bağlama Noktası", style="yellow")
        disk_table.add_column("Toplam")
        disk_table.add_column("Kullanılan")
        disk_table.add_column("Boş")
        disk_table.add_column("Doluluk", justify="right")
        
        for p in disk_usage_data:
            percent = p.get('percent_used_raw', 0)
            style = 'bold red' if percent > 90 else 'yellow' if percent > 75 else 'green'
            disk_table.add_row(
                p.get("device"), 
                p.get("mountpoint"), 
                p.get("total"), 
                p.get("used"), 
                p.get("free"), 
                f"[{style}]{p.get('percent_used')}[/]"
            )
        disk_panel_content.append(disk_table)

    large_items = data.get("En Çok Yer Kaplayanlar (Ev Dizini)")
    if large_items:
        large_items_table = Table(
            title="[dim]En Çok Yer Kaplayan 10 Öğe (Ev Dizini)[/dim]", 
            title_justify="left", 
            box=box.MINIMAL, 
            show_header=True
        )
        large_items_table.add_column("Boyut", style="yellow", justify="right")
        large_items_table.add_column("Dosya / Klasör Yolu", style="cyan")
        
        for item in large_items:
            large_items_table.add_row(item.get('size'), item.get('path'))
        disk_panel_content.append(large_items_table)
    
    if disk_panel_content:
        console.print(Panel(
            Group(*disk_panel_content), 
            title="[bold]3. Disk Analizi[/bold]", 
            border_style="green", 
            expand=False
        ))

    # 4. Ağ Bilgileri
    if data.get("Ağ Bilgileri"):
        console.print(Panel(
            create_info_table(data.get("Ağ Bilgileri")), 
            title="[bold]4. Ağ Bilgileri[/bold]", 
            border_style="green", 
            expand=False
        ))
    
    # 5. Aktif Servisler
    running_services = data.get("Aktif Çalışan Servisler")
    if running_services:
        console.print(Panel(
            Columns(sorted(running_services), equal=True, expand=True), 
            title=f"[bold]5. Aktif Çalışan Servisler ({len(running_services)} adet)[/bold]", 
            border_style="blue", 
            expand=False
        ))

    console.print("\n[yellow]━━━ FAZ 2: ANALİZ VE ÖNERİ ━━━[/yellow]\n")
    
    # 6. Servis Sağlık Analizi
    service_analysis = data.get("Servis Sağlık Analizi", {})
    failed = service_analysis.get("failed", [])
    with_errors = service_analysis.get("with_errors", [])
    
    if failed or with_errors:
        analysis_text = Text()
        panel_style = "red" if failed else "yellow"
        
        if failed:
            analysis_text.append("⛔ ÇÖKMÜŞ (FAILED) SERVİSLER:\n", style="bold red")
            for service in failed:
                analysis_text.append(f"  • {service}\n")
            analysis_text.append(f"\n💡 Düzeltmek için: ", style="cyan")
            analysis_text.append(f"sudo systemctl restart {failed[0]}\n", style="bold cyan")
        
        if with_errors:
            if failed:
                analysis_text.append("\n")
            analysis_text.append("⚠️  ŞÜPHELİ SERVİSLER (Son 24 Saatte Hata Kaydı):\n", style="bold yellow")
            for service in with_errors:
                analysis_text.append(f"  • {service}\n")
            analysis_text.append(f"\n💡 İncelemek için: ", style="cyan")
            analysis_text.append(f"sudo journalctl -u {with_errors[0]} -n 50\n", style="bold cyan")
        
        console.print(Panel(
            analysis_text, 
            title="[bold]6. Servis Sağlık Analizi: DİKKAT[/bold]", 
            border_style=panel_style
        ))
    else:
        console.print(Panel(
            "[green]✓ Tüm servisler sağlıklı çalışıyor.[/green]", 
            title="[bold]6. Servis Sağlık Analizi[/bold]", 
            border_style="green"
        ))

    # 7. Açılış Performansı (Renk Kodlu)
    boot_blame = data.get("Açılış Performans Analizi")
    if boot_blame and isinstance(boot_blame, list) and boot_blame[0].get('time') != 'HATA':
        boot_table = Table(
            box=box.MINIMAL, 
            title="[dim]Açılışı En Çok Yavaşlatan 10 Servis[/dim]", 
            title_justify="left", 
            show_header=True
        )
        boot_table.add_column("Süre", justify="right")
        boot_table.add_column("Servis", style="cyan")
        
        for item in boot_blame:
            time_str, color = format_boot_time_with_color(item.get('time'))
            boot_table.add_row(
                f"[{color}]{time_str}[/]",
                item.get('service')
            )
        
        console.print(Panel(
            boot_table, 
            title="[bold]7. Açılış Performans Analizi[/bold]", 
            subtitle="[dim]Kırmızı: >10s, Sarı: >5s, Varsayılan: >2s, Yeşil: <2s[/dim]",
            border_style="yellow"
        ))

    # 8. Güvenlik Analizi
    security_summary_data = data.get("Güvenlik Özeti")
    if security_summary_data:
        summary_text = Text()
        updates = security_summary_data.get('security_updates_count', -1)
        firewall = security_summary_data.get('firewall_status', 'Bilinmiyor!')
        
        if updates > 0:
            summary_text.append(f"⚠️  Bekleyen {updates} güvenlik güncellemesi var!\n", style="bold yellow")
            summary_text.append("💡 Güncellemek için: ", style="cyan")
            summary_text.append("sudo apt update && sudo apt upgrade\n", style="bold cyan")
        elif updates == 0:
            summary_text.append("✓ Tüm güvenlik güncellemeleri yapılmış.\n", style="green")
        else:
            summary_text.append("? Güvenlik güncellemesi durumu alınamadı.\n", style="dim")

        summary_text.append(f"\n🔥 Güvenlik duvarı (UFW): ", style="white")
        if firewall == "Aktif":
            summary_text.append(f"{firewall}", style="green bold")
        elif firewall == "Devre Dışı":
            summary_text.append(f"{firewall}\n", style="bold red")
            summary_text.append("💡 Aktifleştirmek için: ", style="cyan")
            summary_text.append("sudo ufw enable", style="bold cyan")
        elif firewall == "Kurulu Değil":
            summary_text.append(f"{firewall}\n", style="bold red")
            summary_text.append("💡 Kurmak için: ", style="cyan")
            summary_text.append("sudo apt install ufw && sudo ufw enable", style="bold cyan")
        else:
            summary_text.append(f"{firewall}", style="yellow")
        
        console.print(Panel(
            summary_text, 
            title="[bold]8. Güvenlik Analizi[/bold]", 
            border_style="yellow"
        ))
    
    # 9. S.M.A.R.T. Disk Sağlığı (Detaylı)
    smart_health = data.get("S.M.A.R.T. Disk Sağlığı")
    if smart_health:
        status = smart_health.get('status', 'Bilinmiyor')
        disk_details = smart_health.get('disk_details', [])
        
        # Özet durum
        smart_text = Text()
        smart_text.append(f"Durum: ", style="white")
        
        if status == "İYİ":
            smart_text.append(f"{status} ✓", style="green bold")
        elif status in ["S.M.A.R.T. desteklenmiyor", "BİLGİ YOK"]:
            smart_text.append(f"{status} ℹ️", style="yellow bold")
        else:
            smart_text.append(f"{status} ⚠️", style="red bold")
        
        # Detay tablosu
        if disk_details:
            smart_text.append("\n\n")
            detail_table = Table(box=box.SIMPLE, show_header=True, title="Disk Detayları")
            detail_table.add_column("Disk", style="cyan")
            detail_table.add_column("Model", style="white")
            detail_table.add_column("Durum", style="magenta")
            detail_table.add_column("Sıcaklık", justify="right")
            detail_table.add_column("Çalışma Saati", justify="right")
            
            for disk in disk_details:
                health_style = "green" if disk.get('health_status') in ['PASSED', 'OK'] else "red"
                detail_table.add_row(
                    disk.get('device', 'N/A'),
                    disk.get('model', 'N/A')[:30],  # İlk 30 karakter
                    f"[{health_style}]{disk.get('health_status', 'N/A')}[/]",
                    disk.get('temperature', 'N/A'),
                    disk.get('power_on_hours', 'N/A')
                )
                
                # Uyarılar varsa göster
                if disk.get('warnings'):
                    for warning in disk['warnings']:
                        smart_text.append(f"\n  {warning}", style="yellow")
        
        console.print(Panel(
            Group(smart_text, detail_table) if disk_details else smart_text,
            title="[bold]9. Disk Fiziksel Sağlık (S.M.A.R.T.)[/bold]", 
            border_style="green" if status == "İYİ" else "yellow" if status in ["BİLGİ YOK"] else "red"
        ))
    
    # 10. SSH Güvenlik Denetimi
    ssh_audit = data.get("SSH Güvenlik Denetimi")
    if ssh_audit:
        critical_findings = [f for f in ssh_audit if f.get('level') == 'KRİTİK']
        warning_findings = [f for f in ssh_audit if f.get('level') == 'UYARI']
        
        if critical_findings or warning_findings:
            ssh_text = Text()
            
            if critical_findings:
                ssh_text.append("🔴 KRİTİK SORUNLAR:\n", style="bold red")
                for finding in critical_findings:
                    ssh_text.append(f"  • {finding.get('finding')}\n")
                    ssh_text.append(f"    💡 {finding.get('recommendation')}\n", style="dim")
            
            if warning_findings:
                if critical_findings:
                    ssh_text.append("\n")
                ssh_text.append("🟡 UYARILAR:\n", style="bold yellow")
                for finding in warning_findings:
                    ssh_text.append(f"  • {finding.get('finding')}\n")
                    ssh_text.append(f"    💡 {finding.get('recommendation')}\n", style="dim")
            
            console.print(Panel(
                ssh_text,
                title="[bold]10. SSH Güvenlik Denetimi[/bold]",
                border_style="red" if critical_findings else "yellow"
            ))
    
    # 11. Başarısız Giriş Denemeleri
    failed_logins = data.get("Başarısız Giriş Denemeleri")
    if failed_logins and failed_logins.get('total', 0) > 0:
        login_text = Text()
        total = failed_logins.get('total', 0)
        
        login_text.append(f"Toplam başarısız deneme: {total}\n\n", style="bold yellow")
        
        recent_attacks = failed_logins.get('recent_attacks', [])
        if recent_attacks:
            login_text.append("En çok deneme yapan IP'ler:\n", style="cyan")
            for attack in recent_attacks[:5]:
                login_text.append(f"  • {attack.get('ip')}: {attack.get('attempts')} deneme\n")
            
            login_text.append(f"\n💡 Şüpheli IP'yi engellemek için: ", style="cyan")
            login_text.append(f"sudo ufw deny from {recent_attacks[0].get('ip')}", style="bold cyan")
        
        console.print(Panel(
            login_text,
            title="[bold]11. Başarısız Giriş Denemeleri (Brute-Force Tespiti)[/bold]",
            border_style="yellow" if total < 50 else "red"
        ))
    
    # 12. Eksik PCI Sürücüleri
    missing_drivers = data.get("Eksik PCI Sürücüleri")
    if missing_drivers:
        driver_table = Table(box=box.SIMPLE, show_header=True)
        driver_table.add_column("Aygıt Tipi", style="cyan")
        driver_table.add_column("Aygıt", style="white")
        driver_table.add_column("Durum", style="yellow")
        
        for driver in missing_drivers:
            driver_table.add_row(
                driver.get('type', 'N/A'),
                driver.get('device', 'N/A'),
                driver.get('status', 'N/A')
            )
        
        console.print(Panel(
            driver_table,
            title="[bold]12. Eksik PCI Sürücüleri[/bold]",
            subtitle="[dim]Firmware veya sürücü kurulumu gerekebilir[/dim]",
            border_style="yellow"
        ))
    
    # 13. Dinlemedeki Portlar
    listening_ports = data.get("Dinlemedeki Portlar")
    if listening_ports and isinstance(listening_ports, list):
        if listening_ports[0].get('protocol') != 'HATA':
            port_table = Table(box=box.SIMPLE, show_header=True)
            port_table.add_column("Protokol", style="cyan")
            port_table.add_column("Adres", style="yellow")
            port_table.add_column("Port", style="magenta", justify="right")
            port_table.add_column("İşlem", style="green")
            
            for port in listening_ports[:15]:  # İlk 15'ini göster
                port_table.add_row(
                    port.get('protocol'),
                    port.get('address'),
                    port.get('port'),
                    port.get('process', 'N/A')
                )
            
            console.print(Panel(
                port_table, 
                title=f"[bold]13. Dinlemedeki Portlar ({len(listening_ports)} adet)[/bold]", 
                subtitle="[dim]Dışarıya açık olan ağ portları[/dim]",
                border_style="blue"
            ))
    
    # 14. En Çok Kaynak Kullanan İşlemler
    top_processes = data.get("En Çok Kaynak Kullanan İşlemler")
    if top_processes and isinstance(top_processes, list):
        if top_processes[0].get('user') != 'HATA':
            proc_table = Table(box=box.SIMPLE, show_header=True)
            proc_table.add_column("Kullanıcı", style="cyan")
            proc_table.add_column("CPU %", style="red", justify="right")
            proc_table.add_column("RAM %", style="yellow", justify="right")
            proc_table.add_column("Komut", style="green", overflow="fold")
            
            for proc in top_processes:
                # Komutu kısalt
                cmd = proc.get('command', '')
                if len(cmd) > 60:
                    cmd = cmd[:57] + "..."
                
                proc_table.add_row(
                    proc.get('user'),
                    proc.get('cpu'),
                    proc.get('mem'),
                    cmd
                )
            
            console.print(Panel(
                proc_table, 
                title="[bold]14. En Çok Kaynak Kullanan İşlemler (Top 10)[/bold]", 
                border_style="magenta"
            ))
    
    # =============================================================================
    # ÖZET PANEL - SİSTEM SAĞLIK SKORU
    # =============================================================================
    console.print("\n[yellow]━━━ SİSTEM SAĞLIK RAPORU ━━━[/yellow]\n")
    
    health_score, score_details = calculate_health_score(data)
    emoji = get_health_status_emoji(health_score)
    
    score_text = Text()
    score_text.append(f"\n{emoji} ", style="bold")
    score_text.append(f"SİSTEM SAĞLIK SKORU: ", style="bold white")
    
    if health_score >= 90:
        score_style = "bold green"
        status_text = "MÜKEMİ"
    elif health_score >= 75:
        score_style = "bold yellow"
        status_text = "İYİ"
    elif health_score >= 50:
        score_style = "bold yellow"
        status_text = "ORTA"
    else:
        score_style = "bold red"
        status_text = "KÖTÜ"
    
    score_text.append(f"{health_score}/100", style=score_style)
    score_text.append(f" ({status_text})\n\n", style=score_style)
    
    # Detay skorları
    score_text.append(f"  💾 Disk Sağlığı:  {score_details.get('disk', 0)}/30\n")
    score_text.append(f"  ⚙️  Servisler:     {score_details.get('services', 0)}/25\n")
    score_text.append(f"  🔒 Güvenlik:      {score_details.get('security', 0)}/25\n")
    score_text.append(f"  ⚡ Performans:    {score_details.get('performance', 0)}/20\n")
    
    console.print(Panel(
        score_text,
        title="[bold white]📊 ÖZET RAPOR[/bold white]",
        border_style="cyan",
        expand=False
    ))


# =============================================================================
# ANA PROGRAM
# =============================================================================

def main():
    """Ana program giriş noktası."""
    parser = argparse.ArgumentParser(
        description="Linux Teknikeri - Kapsamlı Sistem Analizi ve Raporlama Aracı",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Örnekler:
  tekniker                              # Normal konsol çıktısı
  tekniker --html-rapor rapor.html      # HTML rapor oluştur
  tekniker --verbose                    # Detaylı hata ayıklama
        """
    )
    parser.add_argument(
        '--html-rapor', 
        type=str, 
        metavar='DOSYA',
        help="Analiz sonuçlarını HTML formatında belirtilen dosyaya kaydeder"
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help="Detaylı hata ayıklama mesajlarını gösterir"
    )
    
    args = parser.parse_args()
    
    # Logging ayarları
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')
    else:
        logging.basicConfig(level=logging.WARNING, format='%(levelname)s: %(message)s')
    
    console = Console()
    
    # Başlık
    console.print("\n" + "="*70, style="cyan")
    console.print("[bold cyan]🐧 LINUX TEKNİKERİ - Kapsamlı Sistem Analizi[/bold cyan]", justify="center")
    console.print("="*70 + "\n", style="cyan")

    # Sudo yetkisi kontrolü
    console.print("[yellow]⚠️  Bu araç, tam analiz için bazı komutlarda 'sudo' yetkisi gerektirir.[/yellow]")
    console.print("[dim](Güvenlik duvarı, S.M.A.R.T. disk sağlığı, ağ portları vb.)[/dim]\n")
    
    try:
        run_command(["sudo", "-v"], timeout=30)
        console.print("[green]✓[/green] Sudo yetkisi alındı.\n")
    except Exception as e:
        console.print(f"[bold red]✗[/bold red] Sudo yetkisi alınamadı: {e}")
        console.print("[yellow]Analiz, sudo gerektirmeyen kontrollerle devam edecek.[/yellow]\n")

    # Veri toplama (İyileştirilmiş progress göstergeli)
    all_data = {}
    total_steps = 15
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("[green]📊 Sistem verileri toplanıyor...", total=total_steps)
        
        # 1. Sistem Envanteri
        progress.update(task, description="[green]📊 Adım 1/15: Sistem envanteri...", advance=1)
        try:
            all_data["Sistem Envanteri"] = get_system_info()
        except Exception as e:
            log.error(f"Sistem Envanteri alınamadı: {e}")
            all_data["Sistem Envanteri"] = {"HATA": str(e)}
        
        # 2. Donanım Envanteri
        progress.update(task, description="[green]📊 Adım 2/15: Donanım envanteri...", advance=1)
        try:
            all_data["Donanım Envanteri"] = get_hardware_info()
        except Exception as e:
            log.error(f"Donanım Envanteri alınamadı: {e}")
            all_data["Donanım Envanteri"] = {"HATA": str(e)}
        
        # 3. GPU Bilgileri
        progress.update(task, description="[green]📊 Adım 3/15: Grafik kartı sürücüleri...", advance=1)
        try:
            all_data["Grafik Sürücü (GPU) Denetimi"] = get_gpu_driver_info()
        except Exception as e:
            log.error(f"GPU bilgisi alınamadı: {e}")
            all_data["Grafik Sürücü (GPU) Denetimi"] = [{"model": "HATA", "driver": str(e)}]
        
        # 4. Disk Kullanımı
        progress.update(task, description="[green]📊 Adım 4/15: Disk kullanımı...", advance=1)
        try:
            all_data["Disk Kullanım Alanları"] = get_disk_usage()
        except Exception as e:
            log.error(f"Disk bilgisi alınamadı: {e}")
            all_data["Disk Kullanım Alanları"] = []
        
        # 5. Büyük Dosyalar
        progress.update(task, description="[green]📊 Adım 5/15: En çok yer kaplayanlar...", advance=1)
        try:
            all_data["En Çok Yer Kaplayanlar (Ev Dizini)"] = get_top_large_items()
        except Exception as e:
            log.error(f"Büyük dosyalar listelenemedi: {e}")
            all_data["En Çok Yer Kaplayanlar (Ev Dizini)"] = []
        
        # 6. Ağ Bilgileri
        progress.update(task, description="[green]📊 Adım 6/15: Ağ yapılandırması...", advance=1)
        try:
            all_data["Ağ Bilgileri"] = get_network_info()
        except Exception as e:
            log.error(f"Ağ bilgisi alınamadı: {e}")
            all_data["Ağ Bilgileri"] = {"HATA": str(e)}
        
        # 7. Servis Analizi
        progress.update(task, description="[green]📊 Adım 7/15: Servis durumları...", advance=1)
        try:
            running_services = get_running_services()
            all_data["Aktif Çalışan Servisler"] = running_services
            all_data["Servis Sağlık Analizi"] = {
                "failed": get_failed_services(),
                "with_errors": get_services_with_errors(running_services)
            }
        except Exception as e:
            log.error(f"Servis bilgileri alınamadı: {e}")
            all_data["Aktif Çalışan Servisler"] = []
            all_data["Servis Sağlık Analizi"] = {"failed": [], "with_errors": []}
        
        # 8. Boot Analizi
        progress.update(task, description="[green]📊 Adım 8/15: Açılış performansı...", advance=1)
        try:
            all_data["Açılış Performans Analizi"] = get_boot_blame()
        except Exception as e:
            log.error(f"Boot analizi alınamadı: {e}")
            all_data["Açılış Performans Analizi"] = []
        
        # 9. Güvenlik Özeti
        progress.update(task, description="[green]📊 Adım 9/15: Güvenlik kontrolü...", advance=1)
        try:
            all_data["Güvenlik