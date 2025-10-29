"""
Linux Teknikeri - Ana Program Modülü (Part 1/2)
=====================================

Kapsamlı sistem analizi ve raporlama aracı.
Pop!_OS, Ubuntu ve Debian tabanlı sistemler için optimize edilmiştir.

Author: ozturu68
Version: 0.4.0
License: MIT
"""

import argparse
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any, Union
import re
import logging
import sys

from rich.console import Console, Group
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich.text import Text
from rich import box
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeElapsedColumn
)
from rich.layout import Layout
from rich.live import Live

# --- İÇE AKTARMALAR ---
from .checks.check_system import get_system_info
from .checks.check_hardware import get_hardware_info
from .checks.check_disk import get_disk_usage, get_top_large_items
from .checks.check_network import get_network_info
from .checks.check_services import (
    get_running_services,
    get_failed_services,
    get_services_with_errors
)
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

# Logger
log = logging.getLogger(__name__)

# Program versi bilgisi
__version__ = "0.4.0"

# =============================================================================
# TÜR TANIMLARI (Type Aliases)
# =============================================================================

SystemData = Dict[str, Any]
HealthScore = Tuple[int, Dict[str, int]]


# =============================================================================
# YARDIMCI FONKSİYONLAR
# =============================================================================

def create_info_table(data: Dict[str, Any], title: Optional[str] = None) -> Table:
    """
    Sözlük verilerini estetik tablo formatına dönüştürür.
    
    Args:
        data: Gösterilecek veri sözlüğü
        title: İsteğe bağlı tablo başlığı
        
    Returns:
        Rich Table nesnesi
        
    Examples:
        >>> table = create_info_table({"cpu": "Intel i7", "ram": "16GB"})
    """
    table = Table(box=box.ROUNDED, padding=(0, 2), title=title, title_style="bold cyan")
    table.add_column("Bileşen", style="cyan", no_wrap=True)
    table.add_column("Değer", style="magenta")
    
    if not isinstance(data, dict):
        table.add_row("[bold red]HATA[/bold red]", "Bu bölüm için veri alınamadı.")
        return table
    
    for key, value in data.items():
        if value is None:
            display_value = "[dim]Yok[/dim]"
        elif isinstance(value, (int, float)):
            display_value = str(value)
        elif isinstance(value, bool):
            display_value = "[green]✓ Evet[/green]" if value else "[red]✗ Hayır[/red]"
        else:
            display_value = str(value)
            
        # Anahtar adını güzelleştir
        formatted_key = key.replace("_", " ").title()
        table.add_row(formatted_key, display_value)
    
    return table


def clean_gpu_model_name(full_model_name: str) -> str:
    """
    GPU model ismini temizler, gereksiz ön ekler ve sürüm bilgilerini kaldırır.
    
    Args:
        full_model_name: Ham GPU model adı (lspci çıktısından)
        
    Returns:
        Temizlenmiş GPU model adı
        
    Examples:
        >>> clean_gpu_model_name("VGA compatible controller: NVIDIA GeForce RTX 3080 (rev a1)")
        'NVIDIA GeForce RTX 3080'
    """
    # "VGA compatible controller: " veya "3D controller: " kısmını kaldır
    match = re.search(r'controller:\s*(.*)', full_model_name, re.IGNORECASE)
    clean_name = match.group(1).strip() if match else full_model_name
    
    # Parantez içindeki (rev XX) kısımlarını temizle
    clean_name = re.sub(r'\s*\([^)]*rev[^)]*\)', '', clean_name).strip()
    
    # Aynı zamanda [subsys ...] gibi köşeli parantez içi bilgileri de temizle
    clean_name = re.sub(r'\s*\[[^\]]*\]', '', clean_name).strip()
    
    return clean_name


def format_size_bytes(size_bytes: Union[int, float]) -> str:
    """
    Byte cinsinden boyutu okunabilir formata çevirir.
    
    Args:
        size_bytes: Byte cinsinden boyut
        
    Returns:
        Okunabilir formatta boyut (örn: "1.5 GB")
        
    Examples:
        >>> format_size_bytes(1073741824)
        '1.0 GB'
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} PB"


def calculate_health_score(data: SystemData) -> HealthScore:
    """
    Sistem sağlık skoru hesaplar (0-100).
    
    Puanlama sistemi:
    - Disk Sağlığı: 30 puan (SMART + Kullanım)
    - Servis Durumu: 25 puan
    - Güvenlik: 25 puan (Güncellemeler + Firewall)
    - Performans: 20 puan (CPU/RAM kullanımı)
    
    Args:
        data: Tüm sistem verilerini içeren sözlük
        
    Returns:
        Tuple: (toplam_skor, detaylı_skorlar)
        
    Examples:
        >>> score, details = calculate_health_score(system_data)
        >>> print(f"Sistem Sağlığı: {score}/100")
    """
    scores = {
        "disk": 0,
        "services": 0,
        "security": 0,
        "performance": 0
    }
    
    # --- 1. DİSK SAĞLIĞI (30 puan) ---
    disk_score = 30
    
    # S.M.A.R.T. kontrolü (15 puan)
    smart_data = data.get("S.M.A.R.T. Disk Sağlığı", {})
    if smart_data.get("status") == "İYİ":
        disk_score -= 0  # Tam puan
    elif smart_data.get("status") == "UYARI":
        disk_score -= 8  # Orta risk
    else:
        disk_score -= 15  # Yüksek risk
    
    # Disk kullanımı (15 puan)
    disk_usage = data.get("Disk Kullanım Alanları", [])
    if disk_usage:
        max_usage = max(
            [d.get("percent_used_raw", 0) for d in disk_usage],
            default=0
        )
        if max_usage > 95:
            disk_score -= 15
        elif max_usage > 85:
            disk_score -= 10
        elif max_usage > 75:
            disk_score -= 5
    
    scores["disk"] = max(0, disk_score)
    
    # --- 2. SERVİS DURUMU (25 puan) ---
    service_score = 25
    service_analysis = data.get("Servis Sağlık Analizi", {})
    
    failed_count = len(service_analysis.get("failed", []))
    error_count = len(service_analysis.get("with_errors", []))
    
    # Her çökmüş servis için -5 puan
    service_score -= min(failed_count * 5, 15)
    # Her hatalı servis için -2 puan
    service_score -= min(error_count * 2, 10)
    
    scores["services"] = max(0, service_score)
    
    # --- 3. GÜVENLİK (25 puan) ---
    security_score = 25
    security_data = data.get("Güvenlik Özeti", {})
    
    # Güvenlik güncellemeleri (15 puan)
    updates = security_data.get("security_updates_count", 0)
    if updates > 10:
        security_score -= 15
    elif updates > 5:
        security_score -= 10
    elif updates > 0:
        security_score -= 5
    
    # Firewall durumu (10 puan)
    firewall = security_data.get("firewall_status", "")
    if firewall == "Devre Dışı" or firewall == "Kurulu Değil":
        security_score -= 10
    
    scores["security"] = max(0, security_score)
    
    # --- 4. PERFORMANS (20 puan) ---
    performance_score = 20
    
    # Top processes verilerinden CPU/RAM kullanımı analizi
    top_procs = data.get("En Çok Kaynak Kullanan İşlemler", [])
    if top_procs and isinstance(top_procs, list) and top_procs[0].get('user') != 'HATA':
        try:
            # En yüksek CPU kullanımını kontrol et
            max_cpu = float(top_procs[0].get("cpu", 0))
            if max_cpu > 90:
                performance_score -= 10
            elif max_cpu > 75:
                performance_score -= 5
        except (ValueError, IndexError, KeyError):
            pass
    
    scores["performance"] = max(0, performance_score)
    
    # Toplam skor
    total_score = sum(scores.values())
    
    return total_score, scores


def get_health_color(score: int) -> str:
    """
    Sağlık skoruna göre renk döndürür.
    
    Args:
        score: Sağlık skoru (0-100)
        
    Returns:
        Rich renk kodu
    """
    if score >= 90:
        return "green"
    elif score >= 75:
        return "yellow"
    elif score >= 50:
        return "orange1"
    else:
        return "red"


# =============================================================================
# RAPOR OLUŞTURMA FONKSİYONLARI
# =============================================================================

def generate_json_report(data: SystemData, filename: str, console: Console) -> bool:
    """
    Toplanan verileri JSON formatında kaydeder.
    
    Args:
        data: Sistem verileri
        filename: Kaydedilecek dosya yolu
        console: Rich Console nesnesi
        
    Returns:
        Başarı durumu
        
    Raises:
        IOError: Dosya yazma hatası
    """
    try:
        # Tarihi ekle
        report_data = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "version": __version__,
                "tool": "Linux Teknikeri",
                "hostname": data.get("Sistem Envanteri", {}).get("hostname", "unknown")
            },
            "data": data
        }
        
        file_path = Path(filename)
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, ensure_ascii=False, indent=2)
        
        console.print(f"\n[green]✓[/green] JSON rapor başarıyla oluşturuldu: [cyan]{filename}[/cyan]")
        console.print(f"[dim]  Dosya boyutu: {format_size_bytes(file_path.stat().st_size)}[/dim]")
        log.info(f"JSON rapor oluşturuldu: {filename}")
        return True
        
    except Exception as e:
        console.print(f"[bold red]✗[/bold red] JSON rapor oluşturulamadı: {e}")
        log.error(f"JSON rapor hatası: {e}", exc_info=True)
        return False

def generate_html_report(
    console: Console,
    data: SystemData,
    filename: str,
    health_score: Optional[HealthScore] = None
) -> None:
    """
    Modern HTML rapor oluşturur - Yeni reporting modülünü kullanır.
    
    Args:
        console: Rich Console nesnesi
        data: Sistem verileri
        filename: Kaydedilecek HTML dosya yolu
        health_score: Sağlık skoru tuple'ı (total_score, score_details)
        
    Note:
        Bootstrap 5 ve Chart.js ile modern, interaktif HTML raporu üretir.
        Responsive tasarım, dark mode desteği, print-friendly.
    """
    try:
        # Yeni modern HTML reporter modülünü kullan
        from .reporting.html_reporter import generate_html_report as create_modern_html
        
        # Health score verilerini data dict'e ekle
        if health_score:
            total_score, score_details = health_score
            data['health_score'] = total_score
            data['disk_health_score'] = score_details.get('disk_health', 0)
            data['services_score'] = score_details.get('services', 0)
            data['security_score'] = score_details.get('security', 0)
            data['performance_score'] = score_details.get('performance', 0)
        else:
            # Eğer health score verilmemişse varsayılan değerler
            data['health_score'] = 0
            data['disk_health_score'] = 0
            data['services_score'] = 0
            data['security_score'] = 0
            data['performance_score'] = 0
        
        # Modern HTML raporunu oluştur
        create_modern_html(data, filename)
        
        # Başarı mesajı
        console.print(f"\n✅ [bold green]Modern HTML rapor oluşturuldu:[/] [cyan]{filename}[/]")
        console.print(f"   [dim]Tarayıcıda açmak için:[/] [yellow]xdg-open {filename}[/]")
        
        # Dosya boyutunu göster
        import os
        file_size = os.path.getsize(filename) / 1024  # KB cinsinden
        console.print(f"   [dim]Dosya boyutu:[/] {file_size:.1f} KB")
        
    except ImportError as e:
        console.print(f"[bold red]❌ HTML reporter modülü yüklenemedi:[/] {e}")
        console.print("[yellow]💡 reporting/html_reporter.py dosyasını kontrol edin[/]")
        
    except Exception as e:
        console.print(f"[bold red]❌ HTML rapor oluşturma hatası:[/] {e}")
        console.print("[yellow]🔍 Detaylı hata bilgisi:[/]")
        
        # Debug için tam hata trace'i
        import traceback
        error_trace = traceback.format_exc()
        console.print(f"[dim]{error_trace}[/]")
        
        console.print("\n[yellow]💡 Sorun giderme önerileri:[/]")
        console.print("   1. reporting/html_reporter.py dosyasının var olduğundan emin olun")
        console.print("   2. Tüm helper fonksiyonların tanımlı olduğunu kontrol edin")
        console.print("   3. --verbose flag'i ile detaylı log alın")

    # Sağlık skoru hesapla (verilmemişse)
    if health_score is None:
        total_score, score_details = calculate_health_score(data)
    else:
        total_score, score_details = health_score
    
    score_color = "#27ae60" if total_score >= 90 else "#f39c12" if total_score >= 75 else "#e74c3c"
    
    html_style = """
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body { 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #2c3e50;
            padding: 20px; 
            line-height: 1.6;
        }
        
        .container { 
            max-width: 1400px; 
            margin: 0 auto; 
            background: #ffffff; 
            border-radius: 15px; 
            box-shadow: 0 10px 40px rgba(0,0,0,0.2); 
            padding: 40px; 
        }
        
        .header {
            text-align: center;
            margin-bottom: 40px;
            padding-bottom: 20px;
            border-bottom: 3px solid #667eea;
        }
        
        .header h1 { 
            color: #2c3e50; 
            font-size: 2.5em;
            margin-bottom: 10px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .header .subtitle {
            color: #7f8c8d;
            font-size: 1.1em;
        }
        
        .health-score {
            text-align: center;
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            padding: 30px;
            border-radius: 15px;
            margin: 30px 0;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        
        .health-score .score-circle {
            width: 150px;
            height: 150px;
            margin: 0 auto 20px;
            border-radius: 50%;
            background: white;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 3em;
            font-weight: bold;
            color: """ + score_color + """;
            box-shadow: 0 5px 20px rgba(0,0,0,0.15);
        }
        
        .score-breakdown {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }
        
        .score-item {
            background: white;
            padding: 15px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
        }
        
        .score-item .label {
            color: #7f8c8d;
            font-size: 0.9em;
            margin-bottom: 5px;
        }
        
        .score-item .value {
            font-size: 1.8em;
            font-weight: bold;
            color: #2c3e50;
        }
        
        h2 { 
            color: #2c3e50;
            border-left: 5px solid #667eea;
            padding-left: 15px;
            margin: 40px 0 20px 0;
            font-size: 1.8em;
        }
        
        h3 {
            color: #34495e;
            margin: 25px 0 15px 0;
            font-size: 1.3em;
        }
        
        table { 
            width: 100%; 
            border-collapse: collapse; 
            margin: 20px 0; 
            background: #fff;
            box-shadow: 0 2px 15px rgba(0,0,0,0.05);
            border-radius: 10px;
            overflow: hidden;
        }
        
        th, td { 
            padding: 15px; 
            border-bottom: 1px solid #ecf0f1;
            text-align: left; 
        }
        
        th { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; 
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.9em;
            letter-spacing: 0.5px;
        }
        
        tr:last-child td {
            border-bottom: none;
        }
        
        tr:hover { 
            background-color: #f8f9fa; 
        }
        
        .panel { 
            border-radius: 10px;
            padding: 20px; 
            margin: 20px 0; 
            background: #ffffff;
            box-shadow: 0 2px 15px rgba(0,0,0,0.08);
        }
        
        .panel.success { 
            border-left: 5px solid #27ae60; 
            background: linear-gradient(to right, #e8f8f5 0%, #ffffff 100%);
        }
        
        .panel.warning { 
            border-left: 5px solid #f39c12; 
            background: linear-gradient(to right, #fef5e7 0%, #ffffff 100%);
        }
        
        .panel.danger { 
            border-left: 5px solid #e74c3c; 
            background: linear-gradient(to right, #fadbd8 0%, #ffffff 100%);
        }
        
        .panel.info { 
            border-left: 5px solid #3498db; 
            background: linear-gradient(to right, #ebf5fb 0%, #ffffff 100%);
        }
        
        .badge { 
            display: inline-block; 
            padding: 5px 12px; 
            border-radius: 20px; 
            font-size: 0.85em; 
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .badge-success { background-color: #27ae60; color: white; }
        .badge-warning { background-color: #f39c12; color: white; }
        .badge-danger { background-color: #e74c3c; color: white; }
        .badge-info { background-color: #3498db; color: white; }
        
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        
        .card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 15px rgba(0,0,0,0.08);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        
        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 5px 25px rgba(0,0,0,0.15);
        }
        
        .card-title {
            font-size: 1.1em;
            font-weight: 600;
            color: #2c3e50;
            margin-bottom: 10px;
            border-bottom: 2px solid #ecf0f1;
            padding-bottom: 10px;
        }
        
        footer { 
            text-align: center; 
            margin-top: 50px; 
            padding-top: 30px; 
            border-top: 2px solid #ecf0f1;
            color: #7f8c8d; 
            font-size: 0.9em; 
        }
        
        .footer-links {
            margin-top: 10px;
        }
        
        .footer-links a {
            color: #667eea;
            text-decoration: none;
            margin: 0 10px;
            transition: color 0.3s ease;
        }
        
        .footer-links a:hover {
            color: #764ba2;
            text-decoration: underline;
        }
        
        ul {
            padding-left: 20px;
        }
        
        ul li {
            margin: 8px 0;
            padding-left: 10px;
        }
        
        code {
            background: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            color: #e74c3c;
        }
        
        @media print {
            body {
                background: white;
                padding: 0;
            }
            .container {
                box-shadow: none;
            }
            .card:hover {
                transform: none;
            }
        }
    </style>
    """
    
    html_content = f"""<!DOCTYPE html>
<html lang='tr'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <meta name='description' content='Linux Teknikeri - Sistem Analiz Raporu'>
    <meta name='author' content='ozturu68'>
    <meta name='generator' content='Linux Teknikeri v{__version__}'>
    <title>Linux Teknikeri - Sistem Analiz Raporu</title>
    {html_style}
</head>
<body>
<div class='container'>
    <div class='header'>
        <h1>🐧 Linux Teknikeri</h1>
        <div class='subtitle'>Kapsamlı Sistem Analiz Raporu</div>
        <p style='margin-top: 15px; color:#95a5a6;'>
            <strong>Oluşturulma:</strong> {datetime.now().strftime('%d %B %Y, %H:%M:%S')} | 
            <strong>Versiyon:</strong> {__version__}
        </p>
    </div>
    
    <!-- Sistem Sağlık Skoru -->
    <div class='health-score'>
        <h2 style='border: none; padding: 0; margin: 0 0 20px 0;'>📊 Sistem Sağlık Skoru</h2>
        <div class='score-circle'>{total_score}</div>
        <p style='font-size: 1.2em; color: #7f8c8d;'>100 üzerinden</p>
        
        <div class='score-breakdown'>
            <div class='score-item'>
                <div class='label'>💾 Disk Sağlığı</div>
                <div class='value'>{score_details.get('disk', 0)}/30</div>
            </div>
            <div class='score-item'>
                <div class='label'>⚙️ Servisler</div>
                <div class='value'>{score_details.get('services', 0)}/25</div>
            </div>
            <div class='score-item'>
                <div class='label'>🔒 Güvenlik</div>
                <div class='value'>{score_details.get('security', 0)}/25</div>
            </div>
            <div class='score-item'>
                <div class='label'>⚡ Performans</div>
                <div class='value'>{score_details.get('performance', 0)}/20</div>
            </div>
        </div>
    </div>
"""
    
    # Sistem Bilgileri
    if data.get("Sistem Envanteri"):
        html_content += "<h2>📋 Sistem Envanteri</h2>"
        html_content += "<div class='grid'>"
        for key, value in data["Sistem Envanteri"].items():
            html_content += f"""
            <div class='card'>
                <div class='card-title'>{key.replace('_', ' ').title()}</div>
                <div style='font-size: 1.1em; color: #34495e;'>{value}</div>
            </div>
            """
        html_content += "</div>"
    
    # Donanım Bilgileri
    if data.get("Donanım Envanteri"):
        html_content += "<h2>💻 Donanım Envanteri</h2><table>"
        html_content += "<thead><tr><th>Bileşen</th><th>Model/Bilgi</th></tr></thead><tbody>"
        for key, value in data["Donanım Envanteri"].items():
            html_content += f"<tr><td>{key.replace('_', ' ').title()}</td><td>{value}</td></tr>"
        html_content += "</tbody></table>"
    
    # GPU Bilgileri
    if data.get("Grafik Sürücü (GPU) Denetimi"):
        html_content += "<h2>🎮 Grafik Kartı ve Sürücüler</h2><table>"
        html_content += "<thead><tr><th>Model</th><th>Sürücü</th></tr></thead><tbody>"
        for gpu in data["Grafik Sürücü (GPU) Denetimi"]:
            model = clean_gpu_model_name(gpu.get('model', 'Bilinmiyor'))
            driver = gpu.get('driver', 'Bilinmiyor')
            driver_badge = "badge-success" if driver not in ['Sürücü Yüklenmemiş', 'nouveau'] else "badge-danger"
            html_content += f"<tr><td>{model}</td><td><span class='badge {driver_badge}'>{driver}</span></td></tr>"
        html_content += "</tbody></table>"
    
    # Disk Kullanımı
    if data.get("Disk Kullanım Alanları"):
        html_content += "<h2>💾 Disk Kullanım Alanları</h2><table>"
        html_content += "<thead><tr><th>Bölüm</th><th>Bağlama Noktası</th><th>Toplam</th><th>Kullanılan</th><th>Boş</th><th>Doluluk</th></tr></thead><tbody>"
        for disk in data["Disk Kullanım Alanları"]:
            percent = disk.get('percent_used_raw', 0)
            badge = "badge-danger" if percent > 90 else "badge-warning" if percent > 75 else "badge-success"
            html_content += f"""<tr>
                <td><code>{disk.get('device')}</code></td>
                <td><code>{disk.get('mountpoint')}</code></td>
                <td>{disk.get('total')}</td>
                <td>{disk.get('used')}</td>
                <td>{disk.get('free')}</td>
                <td><span class='badge {badge}'>{disk.get('percent_used')}</span></td>
            </tr>"""
        html_content += "</tbody></table>"
    
    # Servis Analizi
    if data.get("Servis Sağlık Analizi"):
        failed = data["Servis Sağlık Analizi"].get("failed", [])
        with_errors = data["Servis Sağlık Analizi"].get("with_errors", [])
        
        if failed or with_errors:
            panel_class = "danger" if failed else "warning"
            html_content += f"<div class='panel {panel_class}'>"
            html_content += "<h3>⚠️ Servis Sağlık Analizi</h3>"
            
            if failed:
                html_content += "<h4 style='color: #e74c3c;'>🔴 Çökmüş Servisler:</h4><ul>"
                for service in failed:
                    html_content += f"<li><strong><code>{service}</code></strong></li>"
                html_content += "</ul>"
            
            if with_errors:
                html_content += "<h4 style='color: #f39c12;'>🟡 Şüpheli Servisler (Son 24 Saatte Hata):</h4><ul>"
                for service in with_errors:
                    html_content += f"<li><code>{service}</code></li>"
                html_content += "</ul>"
            
            html_content += "</div>"
        else:
            html_content += "<div class='panel success'>"
            html_content += "<h3>✅ Servis Sağlık Analizi</h3>"
            html_content += "<p>Tüm servisler sağlıklı çalışıyor.</p>"
            html_content += "</div>"
    
    # Güvenlik Özeti
    if data.get("Güvenlik Özeti"):
        security = data["Güvenlik Özeti"]
        updates = security.get('security_updates_count', -1)
        firewall = security.get('firewall_status', 'Bilinmiyor')
        
        panel_class = "danger" if updates > 5 or firewall != "Aktif" else "success"
        html_content += f"<div class='panel {panel_class}'>"
        html_content += "<h3>🔒 Güvenlik Özeti</h3>"
        html_content += f"<p><strong>Bekleyen Güvenlik Güncellemeleri:</strong> "
        
        if updates > 10:
            html_content += f"<span class='badge badge-danger'>{updates}</span>"
        elif updates > 0:
            html_content += f"<span class='badge badge-warning'>{updates}</span>"
        elif updates == 0:
            html_content += f"<span class='badge badge-success'>{updates}</span>"
        else:
            html_content += "Tespit Edilemedi"
            
        html_content += "</p>"
        html_content += f"<p><strong>Güvenlik Duvarı (UFW):</strong> "
        
        if firewall == "Aktif":
            html_content += f"<span class='badge badge-success'>{firewall}</span>"
        else:
            html_content += f"<span class='badge badge-danger'>{firewall}</span>"
            
        html_content += "</p></div>"
    
    # S.M.A.R.T. Disk Sağlığı
    if data.get("S.M.A.R.T. Disk Sağlığı"):
        smart = data["S.M.A.R.T. Disk Sağlığı"]
        status = smart.get('status', 'Bilinmiyor')
        panel_class = "success" if status == "İYİ" else "danger"
        
        html_content += f"<div class='panel {panel_class}'>"
        html_content += f"<h3>🩺 Disk Fiziksel Sağlık (S.M.A.R.T.)</h3>"
        html_content += f"<p><strong>Durum:</strong> <span class='badge badge-{'success' if status == 'İYİ' else 'danger'}'>{status}</span></p>"
        
        if smart.get('failing_disks'):
            html_content += "<h4 style='color: #e74c3c;'>⚠️ Sorunlu Diskler:</h4><ul>"
            for disk in smart['failing_disks']:
                html_content += f"<li><code>{disk}</code></li>"
            html_content += "</ul>"
        html_content += "</div>"
    
    # Açılış Performansı
    if data.get("Açılış Performans Analizi"):
        boot_data = data["Açılış Performans Analizi"]
        if boot_data and boot_data[0].get('time') != 'HATA':
            html_content += "<h2>⚡ Açılış Performans Analizi</h2>"
            html_content += "<table><thead><tr><th>Süre</th><th>Servis</th></tr></thead><tbody>"
            for item in boot_data[:10]:
                html_content += f"<tr><td style='font-weight: bold; color: #e74c3c;'>{item.get('time')}</td><td><code>{item.get('service')}</code></td></tr>"
            html_content += "</tbody></table>"
    
    # Top Processes
    if data.get("En Çok Kaynak Kullanan İşlemler"):
        processes = data["En Çok Kaynak Kullanan İşlemler"]
        if processes and processes[0].get('user') != 'HATA':
            html_content += "<h2>📈 En Çok Kaynak Kullanan İşlemler</h2>"
            html_content += "<table><thead><tr><th>Kullanıcı</th><th>CPU %</th><th>RAM %</th><th>Komut</th></tr></thead><tbody>"
            for proc in processes[:10]:
                cpu = float(proc.get('cpu', 0))
                cpu_color = "#e74c3c" if cpu > 50 else "#f39c12" if cpu > 25 else "#27ae60"
                html_content += f"""<tr>
                    <td>{proc.get('user')}</td>
                    <td style='color: {cpu_color}; font-weight: bold;'>{proc.get('cpu')}%</td>
                    <td>{proc.get('mem')}%</td>
                    <td><code style='font-size: 0.85em;'>{proc.get('command', '')[:80]}</code></td>
                </tr>"""
            html_content += "</tbody></table>"
    
    # Footer
    html_content += f"""
    <footer>
        <p><strong>Linux Teknikeri</strong> v{__version__} - Kapsamlı Sistem Analiz Aracı</p>
        <p>© {datetime.now().year} ozturu68 | Açık Kaynak Proje</p>
        <div class='footer-links'>
            <a href='https://github.com/ozturu68/Linux-Teknikeri' target='_blank'>GitHub</a> |
            <a href='https://github.com/ozturu68/Linux-Teknikeri/issues' target='_blank'>Sorun Bildir</a> |
            <a href='https://github.com/ozturu68/Linux-Teknikeri/blob/main/README.md' target='_blank'>Dokümantasyon</a>
        </div>
    </footer>
</div>
</body>
</html>
"""
    
    try:
        file_path = Path(filename)
        file_path.write_text(html_content, encoding='utf-8')
        console.print(f"\n[green]✓[/green] HTML rapor başarıyla oluşturuldu: [cyan]{filename}[/cyan]")
        console.print(f"[dim]  Dosya boyutu: {format_size_bytes(file_path.stat().st_size)}[/dim]")
    except Exception as e:
        console.print(f"[bold red]✗[/bold red] HTML rapor oluşturulamadı: {e}")
        log.error(f"HTML rapor hatası: {e}", exc_info=True)
        # =============================================================================
# PART 2/2 - KONSOL RAPOR GÖRÜNTÜLEME
# =============================================================================

def display_console_report(console: Console, data: SystemData) -> None:
    """
    Toplanan verileri terminalde modern ve renkli formatta görüntüler.
    
    Args:
        console: Rich Console nesnesi
        data: Tüm sistem verileri
        
    Note:
        Rich kütüphanesi kullanılarak oluşturulmuş, estetik terminal çıktısı.
    """
    
    # Sistem Sağlık Skoru Hesapla
    total_score, score_details = calculate_health_score(data)
    score_color = get_health_color(total_score)
    
    # Sağlık Skoru Paneli
    score_text = Text()
    score_text.append("📊 Sistem Sağlık Skoru: ", style="bold white")
    score_text.append(f"{total_score}/100", style=f"bold {score_color}")
    score_text.append("\n\n")
    score_text.append(f"💾 Disk Sağlığı: {score_details['disk']}/30\n", style="cyan")
    score_text.append(f"⚙️  Servisler: {score_details['services']}/25\n", style="yellow")
    score_text.append(f"🔒 Güvenlik: {score_details['security']}/25\n", style="magenta")
    score_text.append(f"⚡ Performans: {score_details['performance']}/20", style="green")
    
    console.print(Panel(
        score_text,
        title="[bold]💯 GENEL SAĞLIK DURUMU[/bold]",
        border_style=score_color,
        expand=False
    ))
    
    console.print("\n[yellow]━━━ FAZ 1: ENVANTER RAPORLAMA ━━━[/yellow]\n")

    # 1. Sistem Envanteri
    if data.get("Sistem Envanteri"):
        console.print(Panel(
            create_info_table(data["Sistem Envanteri"]),
            title="[bold]1. Sistem Envanteri[/bold]",
            border_style="green",
            expand=False
        ))
    
    # 2. Donanım Envanteri
    if data.get("Donanım Envanteri"):
        console.print(Panel(
            create_info_table(data["Donanım Envanteri"]),
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
        
        if with_errors:
            if failed:
                analysis_text.append("\n")
            analysis_text.append("⚠️  ŞÜPHELİ SERVİSLER (Son 24 Saatte Hata Kaydı):\n", style="bold yellow")
            for service in with_errors:
                analysis_text.append(f"  • {service}\n")
        
        console.print(Panel(
            analysis_text,
            title="[bold]6. Servis Sağlık Analizi: DİKKAT[/bold]",
            subtitle="[dim]İncelemek için: 'systemctl status <servis>' veya 'journalctl -u <servis>'[/dim]",
            border_style=panel_style
        ))
    else:
        console.print(Panel(
            "[green]✓ Tüm servisler sağlıklı çalışıyor.[/green]",
            title="[bold]6. Servis Sağlık Analizi[/bold]",
            border_style="green"
        ))

    # 7. Açılış Performansı
    boot_blame = data.get("Açılış Performans Analizi")
    if boot_blame and isinstance(boot_blame, list) and boot_blame[0].get('time') != 'HATA':
        boot_table = Table(
            box=box.MINIMAL,
            title="[dim]Açılışı En Çok Yavaşlatan 10 Servis[/dim]",
            title_justify="left",
            show_header=True
        )
        boot_table.add_column("Süre", style="red", justify="right")
        boot_table.add_column("Servis", style="cyan")
        
        for item in boot_blame:
            boot_table.add_row(item.get('time'), item.get('service'))
        
        console.print(Panel(
            boot_table,
            title="[bold]7. Açılış Performans Analizi[/bold]",
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
        elif updates == 0:
            summary_text.append("✓ Tüm güvenlik güncellemeleri yapılmış.\n", style="green")
        else:
            summary_text.append("? Güvenlik güncellemesi durumu alınamadı.\n", style="dim")

        summary_text.append(f"\n🔥 Güvenlik duvarı (UFW): ", style="white")
        if firewall == "Aktif":
            summary_text.append(f"{firewall}", style="green bold")
        elif firewall == "Devre Dışı" or firewall == "Kurulu Değil":
            summary_text.append(f"{firewall}", style="bold red")
        else:
            summary_text.append(f"{firewall}", style="yellow")
        
        console.print(Panel(
            summary_text,
            title="[bold]8. Güvenlik Analizi[/bold]",
            border_style="yellow"
        ))
    
    # 9. S.M.A.R.T. Disk Sağlığı
    smart_health = data.get("S.M.A.R.T. Disk Sağlığı")
    if smart_health:
        status = smart_health.get('status', 'Bilinmiyor')
        failing_disks = smart_health.get('failing_disks', [])
        
        smart_text = Text()
        smart_text.append(f"Durum: ", style="white")
        
        if status == "İYİ":
            smart_text.append(f"{status} ✓", style="green bold")
        else:
            smart_text.append(f"{status} ⚠️", style="red bold")
            
            if failing_disks:
                smart_text.append("\n\nDetaylar:\n", style="yellow")
                for disk in failing_disks:
                    smart_text.append(f"  • {disk}\n", style="white")
        
        console.print(Panel(
            smart_text,
            title="[bold]9. Disk Fiziksel Sağlık (S.M.A.R.T.)[/bold]",
            border_style="green" if status == "İYİ" else "red"
        ))
    
    # 10. Dinlemedeki Portlar
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
                title=f"[bold]10. Dinlemedeki Portlar ({len(listening_ports)} adet)[/bold]",
                subtitle="[dim]Dışarıya açık olan ağ portları[/dim]",
                border_style="blue"
            ))
    
    # 11. En Çok Kaynak Kullanan İşlemler
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
                title="[bold]11. En Çok Kaynak Kullanan İşlemler (Top 10)[/bold]",
                border_style="magenta"
            ))


# =============================================================================
# VERİ TOPLAMA FONKSİYONU
# =============================================================================

def collect_system_data(console: Console, verbose: bool = False) -> SystemData:
    """
    Tüm sistem verilerini toplar ve bir sözlük olarak döndürür.
    
    Args:
        console: Rich Console nesnesi (progress bar gösterimi için)
        verbose: Detaylı log gösterimi
        
    Returns:
        Tüm sistem verilerini içeren sözlük
        
    Note:
        Her kontrol try-except bloğu içinde çalışır, bir hata tüm süreci durdurmaz.
    """
    all_data: SystemData = {}
    
    # Progress bar ile veri toplama
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True
    ) as progress:
        
        total_checks = 12
        task = progress.add_task("[cyan]Sistem verileri toplanıyor...", total=total_checks)
        
        # 1. Sistem Envanteri
        progress.update(task, description="[cyan]📋 Sistem bilgileri...")
        try:
            all_data["Sistem Envanteri"] = get_system_info()
            progress.advance(task)
        except Exception as e:
            log.error(f"Sistem Envanteri alınamadı: {e}")
            all_data["Sistem Envanteri"] = {"HATA": str(e)}
            progress.advance(task)
        
        # 2. Donanım Envanteri
        progress.update(task, description="[cyan]💻 Donanım bilgileri...")
        try:
            all_data["Donanım Envanteri"] = get_hardware_info()
            progress.advance(task)
        except Exception as e:
            log.error(f"Donanım Envanteri alınamadı: {e}")
            all_data["Donanım Envanteri"] = {"HATA": str(e)}
            progress.advance(task)
        
        # 3. GPU Bilgileri
        progress.update(task, description="[cyan]🎮 GPU sürücüleri...")
        try:
            all_data["Grafik Sürücü (GPU) Denetimi"] = get_gpu_driver_info()
            progress.advance(task)
        except Exception as e:
            log.error(f"GPU bilgisi alınamadı: {e}")
            all_data["Grafik Sürücü (GPU) Denetimi"] = [{"model": "HATA", "driver": str(e)}]
            progress.advance(task)
        
        # 4. Disk Kullanımı
        progress.update(task, description="[cyan]💾 Disk analizi...")
        try:
            all_data["Disk Kullanım Alanları"] = get_disk_usage()
            progress.advance(task)
        except Exception as e:
            log.error(f"Disk bilgisi alınamadı: {e}")
            all_data["Disk Kullanım Alanları"] = []
            progress.advance(task)
        
        # 5. Büyük Dosyalar
        progress.update(task, description="[cyan]📁 Büyük dosyalar taranıyor...")
        try:
            all_data["En Çok Yer Kaplayanlar (Ev Dizini)"] = get_top_large_items()
            progress.advance(task)
        except Exception as e:
            log.error(f"Büyük dosyalar listelenemedi: {e}")
            all_data["En Çok Yer Kaplayanlar (Ev Dizini)"] = []
            progress.advance(task)
        
        # 6. Ağ Bilgileri
        progress.update(task, description="[cyan]🌐 Ağ yapılandırması...")
        try:
            all_data["Ağ Bilgileri"] = get_network_info()
            progress.advance(task)
        except Exception as e:
            log.error(f"Ağ bilgisi alınamadı: {e}")
            all_data["Ağ Bilgileri"] = {"HATA": str(e)}
            progress.advance(task)
        
        # 7. Servis Analizi
        progress.update(task, description="[cyan]⚙️  Servisler kontrol ediliyor...")
        try:
            running_services = get_running_services()
            all_data["Aktif Çalışan Servisler"] = running_services
            all_data["Servis Sağlık Analizi"] = {
                "failed": get_failed_services(),
                "with_errors": get_services_with_errors(running_services)
            }
            progress.advance(task)
        except Exception as e:
            log.error(f"Servis bilgileri alınamadı: {e}")
            all_data["Aktif Çalışan Servisler"] = []
            all_data["Servis Sağlık Analizi"] = {"failed": [], "with_errors": []}
            progress.advance(task)
        
        # 8. Boot Performansı
        progress.update(task, description="[cyan]⚡ Açılış analizi...")
        try:
            all_data["Açılış Performans Analizi"] = get_boot_blame()
            progress.advance(task)
        except Exception as e:
            log.error(f"Boot analizi alınamadı: {e}")
            all_data["Açılış Performans Analizi"] = []
            progress.advance(task)
        
        # 9. Güvenlik
        progress.update(task, description="[cyan]🔒 Güvenlik kontrolü...")
        try:
            all_data["Güvenlik Özeti"] = get_security_summary()
            progress.advance(task)
        except Exception as e:
            log.error(f"Güvenlik özeti alınamadı: {e}")
            all_data["Güvenlik Özeti"] = {}
            progress.advance(task)
        
        # 10. S.M.A.R.T.
        progress.update(task, description="[cyan]🩺 Disk sağlık kontrolü...")
        try:
            all_data["S.M.A.R.T. Disk Sağlığı"] = check_smart_health()
            progress.advance(task)
        except Exception as e:
            log.error(f"S.M.A.R.T. kontrolü yapılamadı: {e}")
            all_data["S.M.A.R.T. Disk Sağlığı"] = {"status": "HATA", "failing_disks": [str(e)]}
            progress.advance(task)
        
        # 11. Açık Portlar
        progress.update(task, description="[cyan]🌐 Ağ portları taranıyor...")
        try:
            all_data["Dinlemedeki Portlar"] = get_listening_ports()
            progress.advance(task)
        except Exception as e:
            log.error(f"Port listesi alınamadı: {e}")
            all_data["Dinlemedeki Portlar"] = []
            progress.advance(task)
        
        # 12. Top Processes
        progress.update(task, description="[cyan]📊 İşlem analizi...")
        try:
            all_data["En Çok Kaynak Kullanan İşlemler"] = get_top_processes()
            progress.advance(task)
        except Exception as e:
            log.error(f"İşlem listesi alınamadı: {e}")
            all_data["En Çok Kaynak Kullanan İşlemler"] = []
            progress.advance(task)
    
    return all_data


# =============================================================================
# ANA PROGRAM
# =============================================================================

def main():
    """
    Ana program giriş noktası.
    
    CLI argümanlarını parse eder, veri toplar ve rapor üretir.
    """
    parser = argparse.ArgumentParser(
        description="Linux Teknikeri - Kapsamlı Sistem Analizi ve Raporlama Aracı",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Örnekler:
  linux-teknikeri                                 # Normal konsol çıktısı
  linux-teknikeri --html rapor.html               # HTML rapor oluştur
  linux-teknikeri --json data.json                # JSON rapor oluştur
  linux-teknikeri --html rapor.html --json data.json  # Her ikisi birden
  linux-teknikeri --verbose                       # Detaylı hata ayıklama
  
Daha fazla bilgi: https://github.com/ozturu68/Linux-Teknikeri
        """
    )
    
    parser.add_argument(
        '--html',
        type=str,
        metavar='DOSYA',
        dest='html_file',
        help="Analiz sonuçlarını HTML formatında belirtilen dosyaya kaydeder"
    )
    
    parser.add_argument(
        '--json',
        type=str,
        metavar='DOSYA',
        dest='json_file',
        help="Analiz sonuçlarını JSON formatında belirtilen dosyaya kaydeder"
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help="Detaylı hata ayıklama mesajlarını gösterir"
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version=f'Linux Teknikeri v{__version__}'
    )
    
    parser.add_argument(
        '--no-sudo-check',
        action='store_true',
        help="Sudo yetkisi kontrolünü atla"
    )
    
    args = parser.parse_args()
    
    # Logging ayarları
    if args.verbose:
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    else:
        logging.basicConfig(
            level=logging.WARNING,
            format='%(levelname)s: %(message)s'
        )
    
    console = Console()
    
    # Başlık
    console.print("\n" + "="*70, style="cyan")
    console.print("[bold cyan]🐧 LINUX TEKNİKERİ - Kapsamlı Sistem Analizi[/bold cyan]", justify="center")
    console.print(f"[dim]v{__version__} | © 2025 ozturu68[/dim]", justify="center")
    console.print("="*70 + "\n", style="cyan")

    # Sudo yetkisi kontrolü
    if not args.no_sudo_check:
        console.print("[yellow]⚠️  Bu araç, tam analiz için bazı komutlarda 'sudo' yetkisi gerektirir.[/yellow]")
        console.print("[dim](Güvenlik duvarı, S.M.A.R.T. disk sağlığı, ağ portları vb.)[/dim]\n")
        
        try:
            stdout, stderr, retcode = run_command(["sudo", "-v"], timeout=30)
            if retcode == 0:
                console.print("[green]✓[/green] Sudo yetkisi alındı.\n")
            else:
                console.print(f"[bold yellow]⚠[/bold yellow] Sudo yetkisi alınamadı.")
                console.print("[dim]Analiz, sudo gerektirmeyen kontrollerle devam edecek.[/dim]\n")
        except Exception as e:
            console.print(f"[bold yellow]⚠[/bold yellow] Sudo kontrolü yapılamadı: {e}")
            console.print("[dim]Analiz devam ediyor...[/dim]\n")
    
    # Başlangıç zamanı
    start_time = time.time()
    
    # Veri toplama
    console.print("[bold green]📊 Sistem verileri toplanıyor...[/bold green]\n")
    all_data = collect_system_data(console, args.verbose)
    
    # Toplama süresi
    elapsed_time = time.time() - start_time
    console.print(f"\n[green]✓[/green] Veri toplama tamamlandı ([cyan]{elapsed_time:.2f}s[/cyan]).\n")
    
    # Sağlık skoru hesapla
    total_score, score_details = calculate_health_score(all_data)
    
    # Rapor üretimi
    report_generated = False
    
    if args.json_file:
        console.print("[bold blue]📄 JSON rapor oluşturuluyor...[/bold blue]")
        if generate_json_report(all_data, args.json_file, console):
            report_generated = True
    
    if args.html_file:
        console.print("[bold blue]📄 HTML rapor oluşturuluyor...[/bold blue]")
        generate_html_report(console, all_data, args.html_file, (total_score, score_details))
        report_generated = True
    
    # Konsol raporu (dosya raporu oluşturulmamışsa veya her durumda)
    if not report_generated or not (args.html_file or args.json_file):
        display_console_report(console, all_data)
    else:
        # Sadece sağlık skorunu göster
        score_color = get_health_color(total_score)
        console.print(Panel(
            f"[{score_color}]Sistem Sağlık Skoru: {total_score}/100[/]",
            title="[bold]📊 Özet[/bold]",
            border_style=score_color
        ))
    
    # Toplam süre
    total_elapsed = time.time() - start_time
    console.print(f"\n[green]✓[/green] Analiz tamamlandı! ([cyan]Toplam süre: {total_elapsed:.2f}s[/cyan])")
    
    # Çıkış kodu (sağlık skoruna göre)
    if total_score >= 90:
        console.print("[green]🎉 Sistem mükemmel durumda![/green]\n")
        sys.exit(0)
    elif total_score >= 75:
        console.print("[yellow]⚠️  Sisteminizde bazı uyarılar var.[/yellow]\n")
        sys.exit(0)
    elif total_score >= 50:
        console.print("[orange1]⚠️  Sisteminizde dikkat edilmesi gereken sorunlar var.[/orange1]\n")
        sys.exit(1)
    else:
        console.print("[red]🔴 Sisteminizde kritik sorunlar tespit edildi![/red]\n")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console = Console()
        console.print("\n[yellow]⚠️  Analiz kullanıcı tarafından iptal edildi.[/yellow]")
        sys.exit(130)
    except Exception as e:
        console = Console()
        console.print(f"\n[bold red]❌ Kritik hata:[/bold red] {e}")
        log.critical(f"Program kritik hata ile sonlandı: {e}", exc_info=True)
        sys.exit(1)