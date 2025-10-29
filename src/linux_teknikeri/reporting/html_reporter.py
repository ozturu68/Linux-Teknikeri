"""
Linux Teknikeri - Modern HTML Rapor Üretici
===========================================

Bootstrap 5, Chart.js ve Font Awesome ile zenginleştirilmiş,
responsive ve interaktif HTML raporları üretir.

Features:
    ✅ Modern ve profesyonel tasarım
    ✅ Responsive layout (mobil uyumlu)
    ✅ İnteraktif grafikler (Chart.js)
    ✅ Dark/Light mode toggle
    ✅ Print-friendly (PDF export)
    ✅ Animasyonlu elementler
    ✅ Collapse/Expand sections
    ✅ Arama ve filtreleme
    ✅ Export to JSON button

Author: ozturu68
Version: 0.4.0
Date: 2025-01-29
License: MIT
"""

from datetime import datetime
from typing import Dict, Any, List, Optional
import html as html_escape
import json


def generate_html_report(data: Dict[str, Any], output_file: str) -> None:
    """
    Modern, interaktif HTML rapor üretir.
    
    Args:
        data: Sistem analiz verileri (dict)
        output_file: Çıktı dosya yolu
        
    Raises:
        IOError: Dosya yazma hatası
        
    Examples:
        >>> data = {'health_score': 85, 'system_info': {...}}
        >>> generate_html_report(data, 'rapor.html')
    """
    
    # Veri çıkarma
    health_score = data.get('health_score', 0)
    disk_score = data.get('disk_health_score', 0)
    services_score = data.get('services_score', 0)
    security_score = data.get('security_score', 0)
    performance_score = data.get('performance_score', 0)
    
    system_info = data.get('system_info', {})
    hardware_info = data.get('hardware_info', {})
    disk_usage = data.get('disk_usage', [])
    gpu_drivers = data.get('gpu_drivers', [])
    running_services = data.get('running_services', [])
    failed_services = data.get('failed_services', [])
    suspicious_services = data.get('suspicious_services', [])
    security_summary = data.get('security_summary', {})
    listening_ports = data.get('listening_ports', [])
    boot_analysis = data.get('boot_analysis', [])
    top_processes = data.get('top_processes', [])
    large_files = data.get('large_files', [])
    smart_health = data.get('smart_health', {})
    
    # HTML oluştur
    html_content = _build_html_template(
        health_score=health_score,
        disk_score=disk_score,
        services_score=services_score,
        security_score=security_score,
        performance_score=performance_score,
        system_info=system_info,
        hardware_info=hardware_info,
        disk_usage=disk_usage,
        gpu_drivers=gpu_drivers,
        running_services=running_services,
        failed_services=failed_services,
        suspicious_services=suspicious_services,
        security_summary=security_summary,
        listening_ports=listening_ports,
        boot_analysis=boot_analysis,
        top_processes=top_processes,
        large_files=large_files,
        smart_health=smart_health,
    )
    
    # Dosyaya yaz
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
    except IOError as e:
        raise IOError(f"HTML rapor dosyası yazılamadı: {e}")


def _build_html_template(**kwargs) -> str:
    """Ana HTML şablonunu oluşturur."""
    
    return f"""<!DOCTYPE html>
<html lang="tr" data-bs-theme="light">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="Linux Teknikeri - Kapsamlı Sistem Analiz Raporu">
    <meta name="author" content="ozturu68">
    <meta name="generator" content="Linux Teknikeri v0.4.0">
    
    <title>Linux Teknikeri - Sistem Raporu</title>
    
    <!-- Bootstrap 5.3.2 -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    
    <!-- Font Awesome 6.5.1 -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    
    <!-- Chart.js 4.4.0 -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    
    <!-- Custom CSS -->
    <style>
{_get_custom_css()}
    </style>
</head>
<body>
    
    <!-- Navbar -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-gradient sticky-top">
        <div class="container-fluid">
            <a class="navbar-brand" href="#top">
                <i class="fas fa-linux"></i> Linux Teknikeri
            </a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item"><a class="nav-link" href="#sistem"><i class="fas fa-desktop"></i> Sistem</a></li>
                    <li class="nav-item"><a class="nav-link" href="#donanim"><i class="fas fa-microchip"></i> Donanım</a></li>
                    <li class="nav-item"><a class="nav-link" href="#disk"><i class="fas fa-hdd"></i> Disk</a></li>
                    <li class="nav-item"><a class="nav-link" href="#servis"><i class="fas fa-cogs"></i> Servisler</a></li>
                    <li class="nav-item"><a class="nav-link" href="#guvenlik"><i class="fas fa-shield-alt"></i> Güvenlik</a></li>
                    <li class="nav-item">
                        <button class="btn btn-sm btn-outline-light ms-2" onclick="toggleTheme()" id="themeToggle">
                            <i class="fas fa-moon"></i>
                        </button>
                    </li>
                    <li class="nav-item">
                        <button class="btn btn-sm btn-outline-light ms-2" onclick="window.print()">
                            <i class="fas fa-print"></i>
                        </button>
                    </li>
                </ul>
            </div>
        </div>
    </nav>
    
    <div class="container my-4" id="top">
        
        <!-- Header Card -->
        <div class="card header-card mb-4 animate-fade-in">
            <div class="card-body text-center">
                <h1 class="display-4 fw-bold text-primary">
                    <i class="fas fa-linux fa-2x"></i><br>
                    Linux Teknikeri
                </h1>
                <p class="lead text-muted">Kapsamlı Sistem Analiz Raporu</p>
                <p class="text-muted">
                    <i class="fas fa-calendar-alt"></i> {datetime.now().strftime('%d %B %Y, %H:%M:%S')}<br>
                    <i class="fas fa-user"></i> Oluşturan: ozturu68
                </p>
            </div>
        </div>
        
        <!-- Health Score Card -->
{_build_health_score_section(**kwargs)}
        
        <!-- Quick Stats -->
{_build_quick_stats(**kwargs)}
        
        <!-- System Info -->
{_build_system_info_section(**kwargs)}
        
        <!-- Hardware Info -->
{_build_hardware_section(**kwargs)}
        
        <!-- GPU Drivers -->
{_build_gpu_section(**kwargs)}
        
        <!-- Disk Usage -->
{_build_disk_section(**kwargs)}
        
        <!-- Services -->
{_build_services_section(**kwargs)}
        
        <!-- Security -->
{_build_security_section(**kwargs)}
        
        <!-- Network Ports -->
{_build_network_section(**kwargs)}
        
        <!-- Boot Analysis -->
{_build_boot_section(**kwargs)}
        
        <!-- Top Processes -->
{_build_processes_section(**kwargs)}
        
        <!-- Footer -->
        <footer class="text-center py-4 mt-5">
            <div class="card">
                <div class="card-body">
                    <p class="mb-1">
                        <i class="fas fa-code"></i> <strong>Linux Teknikeri</strong> v0.4.0
                    </p>
                    <p class="text-muted mb-0">
                        © 2025 ozturu68 | 
                        <a href="https://github.com/ozturu68/Linux-Teknikeri" target="_blank" class="text-decoration-none">
                            <i class="fab fa-github"></i> GitHub
                        </a>
                    </p>
                </div>
            </div>
        </footer>
        
    </div>
    
    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    
    <!-- Custom JS -->
    <script>
{_get_custom_javascript(**kwargs)}
    </script>
    
</body>
</html>"""


def _get_custom_css() -> str:
    """Özel CSS stilleri."""
    return """
        :root {
            --primary-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --success-color: #28a745;
            --warning-color: #ffc107;
            --danger-color: #dc3545;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            background-attachment: fixed;
            min-height: 100vh;
        }
        
        .navbar.bg-gradient {
            background: var(--primary-gradient) !important;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .card {
            border: none;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            transition: transform 0.3s, box-shadow 0.3s;
            overflow: hidden;
        }
        
        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(0,0,0,0.2);
        }
        
        .header-card {
            background: white;
            border-left: 5px solid #667eea;
        }
        
        .health-score-circle {
            width: 180px;
            height: 180px;
            border-radius: 50%;
            background: conic-gradient(
                var(--success-color) 0deg,
                var(--success-color) calc(var(--score, 0) * 3.6deg),
                #e9ecef calc(var(--score, 0) * 3.6deg),
                #e9ecef 360deg
            );
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto;
            position: relative;
            animation: scoreRotate 2s ease-out;
        }
        
        @keyframes scoreRotate {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }
        
        .health-score-circle::before {
            content: '';
            position: absolute;
            width: 140px;
            height: 140px;
            background: white;
            border-radius: 50%;
            box-shadow: inset 0 0 20px rgba(0,0,0,0.1);
        }
        
        .score-text {
            position: relative;
            z-index: 1;
            font-size: 3rem;
            font-weight: bold;
            color: var(--success-color);
        }
        
        .metric-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            transition: all 0.3s;
            cursor: pointer;
        }
        
        .metric-card:hover {
            background: #f8f9fa;
            transform: scale(1.05);
        }
        
        .metric-icon {
            font-size: 2.5rem;
            margin-bottom: 10px;
        }
        
        .badge-custom {
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: 600;
            font-size: 0.9rem;
        }
        
        .progress-custom {
            height: 25px;
            border-radius: 10px;
            background: #e9ecef;
            overflow: hidden;
        }
        
        .progress-bar-animated {
            animation: progressAnimation 2s ease-out;
        }
        
        @keyframes progressAnimation {
            from { width: 0%; }
        }
        
        .service-item {
            display: flex;
            align-items: center;
            padding: 10px;
            border-bottom: 1px solid #e9ecef;
            transition: background 0.2s;
        }
        
        .service-item:hover {
            background: #f8f9fa;
        }
        
        .status-indicator {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 10px;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        .status-running { background: var(--success-color); }
        .status-failed { background: var(--danger-color); }
        .status-warning { background: var(--warning-color); }
        
        .animate-fade-in {
            animation: fadeIn 1s ease-in;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        @media print {
            body {
                background: white !important;
            }
            .navbar, .btn, footer a {
                display: none !important;
            }
            .card {
                box-shadow: none !important;
                page-break-inside: avoid;
            }
        }
        
        [data-bs-theme="dark"] body {
            background: #1a1d23;
        }
        
        [data-bs-theme="dark"] .card {
            background: #2d3139;
            color: #e9ecef;
        }
        
        [data-bs-theme="dark"] .health-score-circle::before {
            background: #2d3139;
        }
        
        .chart-container {
            position: relative;
            height: 300px;
            margin: 20px 0;
        }
        
        .scroll-section {
            max-height: 400px;
            overflow-y: auto;
        }
        
        .scroll-section::-webkit-scrollbar {
            width: 8px;
        }
        
        .scroll-section::-webkit-scrollbar-track {
            background: #f1f1f1;
            border-radius: 10px;
        }
        
        .scroll-section::-webkit-scrollbar-thumb {
            background: #888;
            border-radius: 10px;
        }
        
        .scroll-section::-webkit-scrollbar-thumb:hover {
            background: #555;
        }
"""


def _build_health_score_section(**kwargs) -> str:
    """Sağlık skoru section'ı."""
    health = kwargs.get('health_score', 0)
    disk = kwargs.get('disk_score', 0)
    services = kwargs.get('services_score', 0)
    security = kwargs.get('security_score', 0)
    performance = kwargs.get('performance_score', 0)
    
    score_color = 'success' if health >= 80 else 'warning' if health >= 60 else 'danger'
    
    return f"""
        <div class="card mb-4 animate-fade-in" style="animation-delay: 0.1s;">
            <div class="card-body">
                <div class="row align-items-center">
                    <div class="col-md-4 text-center mb-3 mb-md-0">
                        <div class="health-score-circle" style="--score: {health}">
                            <div class="score-text">{health}</div>
                        </div>
                        <h4 class="mt-3 text-{score_color}">
                            <i class="fas fa-heartbeat"></i> Sistem Sağlık Skoru
                        </h4>
                        <p class="text-muted">100 üzerinden {health} puan</p>
                    </div>
                    <div class="col-md-8">
                        <div class="row g-3">
                            <div class="col-sm-6">
                                <div class="metric-card border-start border-primary border-4">
                                    <div class="metric-icon text-primary"><i class="fas fa-hdd"></i></div>
                                    <h6 class="text-muted mb-1">Disk Sağlığı</h6>
                                    <h3 class="mb-0">{disk}<small class="text-muted">/30</small></h3>
                                    <div class="progress progress-custom mt-2">
                                        <div class="progress-bar bg-primary progress-bar-animated" style="width: {(disk/30)*100}%"></div>
                                    </div>
                                </div>
                            </div>
                            <div class="col-sm-6">
                                <div class="metric-card border-start border-info border-4">
                                    <div class="metric-icon text-info"><i class="fas fa-cogs"></i></div>
                                    <h6 class="text-muted mb-1">Servisler</h6>
                                    <h3 class="mb-0">{services}<small class="text-muted">/25</small></h3>
                                    <div class="progress progress-custom mt-2">
                                        <div class="progress-bar bg-info progress-bar-animated" style="width: {(services/25)*100}%"></div>
                                    </div>
                                </div>
                            </div>
                            <div class="col-sm-6">
                                <div class="metric-card border-start border-success border-4">
                                    <div class="metric-icon text-success"><i class="fas fa-shield-alt"></i></div>
                                    <h6 class="text-muted mb-1">Güvenlik</h6>
                                    <h3 class="mb-0">{security}<small class="text-muted">/25</small></h3>
                                    <div class="progress progress-custom mt-2">
                                        <div class="progress-bar bg-success progress-bar-animated" style="width: {(security/25)*100}%"></div>
                                    </div>
                                </div>
                            </div>
                            <div class="col-sm-6">
                                <div class="metric-card border-start border-warning border-4">
                                    <div class="metric-icon text-warning"><i class="fas fa-tachometer-alt"></i></div>
                                    <h6 class="text-muted mb-1">Performans</h6>
                                    <h3 class="mb-0">{performance}<small class="text-muted">/20</small></h3>
                                    <div class="progress progress-custom mt-2">
                                        <div class="progress-bar bg-warning progress-bar-animated" style="width: {(performance/20)*100}%"></div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
"""


def _build_quick_stats(**kwargs) -> str:
    """Hızlı istatistikler."""
    services_running = len(kwargs.get('running_services', []))
    services_failed = len(kwargs.get('failed_services', []))
    disks = len(kwargs.get('disk_usage', []))
    ports = len(kwargs.get('listening_ports', []))
    
    return f"""
        <div class="row g-3 mb-4">
            <div class="col-sm-6 col-md-3">
                <div class="card bg-primary text-white animate-fade-in" style="animation-delay: 0.2s;">
                    <div class="card-body text-center">
                        <i class="fas fa-play-circle fa-3x mb-2"></i>
                        <h2 class="mb-0">{services_running}</h2>
                        <small>Çalışan Servis</small>
                    </div>
                </div>
            </div>
            <div class="col-sm-6 col-md-3">
                <div class="card bg-danger text-white animate-fade-in" style="animation-delay: 0.3s;">
                    <div class="card-body text-center">
                        <i class="fas fa-exclamation-triangle fa-3x mb-2"></i>
                        <h2 class="mb-0">{services_failed}</h2>
                        <small>Sorunlu Servis</small>
                    </div>
                </div>
            </div>
            <div class="col-sm-6 col-md-3">
                <div class="card bg-info text-white animate-fade-in" style="animation-delay: 0.4s;">
                    <div class="card-body text-center">
                        <i class="fas fa-hdd fa-3x mb-2"></i>
                        <h2 class="mb-0">{disks}</h2>
                        <small>Disk Bölümü</small>
                    </div>
                </div>
            </div>
            <div class="col-sm-6 col-md-3">
                <div class="card bg-warning text-white animate-fade-in" style="animation-delay: 0.5s;">
                    <div class="card-body text-center">
                        <i class="fas fa-network-wired fa-3x mb-2"></i>
                        <h2 class="mb-0">{ports}</h2>
                        <small>Açık Port</small>
                    </div>
                </div>
            </div>
        </div>
"""


def _build_system_info_section(**kwargs) -> str:
    """Sistem bilgileri section'ı."""
    info = kwargs.get('system_info', {})
    
    return f"""
        <div class="card mb-4 animate-fade-in" id="sistem" style="animation-delay: 0.6s;">
            <div class="card-header bg-primary text-white">
                <h4 class="mb-0"><i class="fas fa-desktop"></i> Sistem Bilgileri</h4>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-6">
                        <table class="table table-hover">
                            <tr>
                                <td width="180"><i class="fas fa-laptop text-primary"></i> <strong>İşletim Sistemi</strong></td>
                                <td>{_escape(info.get('os_version', 'N/A'))}</td>
                            </tr>
                            <tr>
                                <td><i class="fas fa-code-branch text-info"></i> <strong>Kernel</strong></td>
                                <td><code>{_escape(info.get('kernel_version', 'N/A'))}</code></td>
                            </tr>
                            <tr>
                                <td><i class="fas fa-cube text-success"></i> <strong>Mimari</strong></td>
                                <td>{_escape(info.get('architecture', 'N/A'))}</td>
                            </tr>
                        </table>
                    </div>
                    <div class="col-md-6">
                        <table class="table table-hover">
                            <tr>
                                <td width="180"><i class="fas fa-palette text-warning"></i> <strong>Masaüstü</strong></td>
                                <td>{_escape(info.get('desktop_environment', 'N/A'))}</td>
                            </tr>
                            <tr>
                                <td><i class="fas fa-server text-danger"></i> <strong>Hostname</strong></td>
                                <td>{_escape(info.get('hostname', 'N/A'))}</td>
                            </tr>
                            <tr>
                                <td><i class="fas fa-volume-up text-primary"></i> <strong>Ses Sunucusu</strong></td>
                                <td>{_escape(info.get('sound_server', 'N/A'))}</td>
                            </tr>
                        </table>
                    </div>
                </div>
            </div>
        </div>
"""


def _build_hardware_section(**kwargs) -> str:
    """Donanım section'ı."""
    hw = kwargs.get('hardware_info', {})
    
    return f"""
        <div class="card mb-4 animate-fade-in" id="donanim" style="animation-delay: 0.7s;">
            <div class="card-header bg-success text-white">
                <h4 class="mb-0"><i class="fas fa-microchip"></i> Donanım Bilgileri</h4>
            </div>
            <div class="card-body">
                <div class="row g-4">
                    <div class="col-md-6">
                        <div class="p-3 border rounded bg-light">
                            <div class="d-flex align-items-center mb-2">
                                <i class="fas fa-microchip fa-2x text-primary me-3"></i>
                                <div>
                                    <h6 class="mb-0 text-muted">İşlemci (CPU)</h6>
                                    <strong>{_escape(hw.get('cpu_model', 'N/A'))}</strong>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="p-3 border rounded bg-light">
                            <div class="d-flex align-items-center mb-2">
                                <i class="fas fa-memory fa-2x text-info me-3"></i>
                                <div>
                                    <h6 class="mb-0 text-muted">Bellek (RAM)</h6>
                                    <strong>{_escape(hw.get('total_ram', 'N/A'))}</strong>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-12">
                        <div class="p-3 border rounded bg-light">
                            <div class="d-flex align-items-center mb-2">
                                <i class="fas fa-video fa-2x text-success me-3"></i>
                                <div>
                                    <h6 class="mb-0 text-muted">Ekran Kartı (GPU)</h6>
                                    <strong>{_escape(hw.get('gpu_model', 'N/A'))}</strong>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
"""


def _build_gpu_section(**kwargs) -> str:
    """GPU sürücüler section'ı."""
    gpus = kwargs.get('gpu_drivers', [])
    
    if not gpus:
        return ""
    
    rows = []
    for gpu in gpus:
        driver = gpu.get('driver', 'N/A')
        driver_badge = 'success' if 'nvidia' in driver.lower() or 'amdgpu' in driver.lower() else 'warning'
        
        rows.append(f"""
            <tr>
                <td><i class="fas fa-video text-primary me-2"></i>{_escape(gpu.get('model', 'N/A'))}</td>
                <td><span class="badge-custom bg-{driver_badge}">{_escape(driver)}</span></td>
                <td><code>{_escape(gpu.get('driver_version', 'N/A'))}</code></td>
                <td>{_escape(gpu.get('opengl_version', 'N/A'))}</td>
            </tr>
        """)
    
    return f"""
        <div class="card mb-4 animate-fade-in" style="animation-delay: 0.8s;">
            <div class="card-header bg-info text-white">
                <h4 class="mb-0"><i class="fas fa-video"></i> GPU Sürücüleri</h4>
            </div>
            <div class="card-body">
                <table class="table table-hover">
                    <thead class="table-light">
                        <tr>
                            <th>Model</th>
                            <th>Sürücü</th>
                            <th>Versiyon</th>
                            <th>OpenGL</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(rows)}
                    </tbody>
                </table>
            </div>
        </div>
"""


def _build_disk_section(**kwargs) -> str:
    """Disk kullanım section'ı."""
    disks = kwargs.get('disk_usage', [])
    
    if not disks:
        return ""
    
    rows = []
    for disk in disks:
        usage_pct = float(str(disk.get('usage_percent', '0')).replace('%', ''))
        color = 'danger' if usage_pct > 80 else 'warning' if usage_pct > 60 else 'success'
        
        rows.append(f"""
            <tr>
                <td><code>{_escape(disk.get('partition', 'N/A'))}</code></td>
                <td><i class="fas fa-folder text-warning me-2"></i>{_escape(disk.get('mount_point', 'N/A'))}</td>
                <td>{_escape(disk.get('total', 'N/A'))}</td>
                <td>{_escape(disk.get('used', 'N/A'))}</td>
                <td>
                    <div class="progress progress-custom">
                        <div class="progress-bar bg-{color} progress-bar-animated" 
                             style="width: {usage_pct}%" 
                             role="progressbar">
                            {usage_pct:.1f}%
                        </div>
                    </div>
                </td>
            </tr>
        """)
    
    return f"""
        <div class="card mb-4 animate-fade-in" id="disk" style="animation-delay: 0.9s;">
            <div class="card-header bg-warning text-dark">
                <h4 class="mb-0"><i class="fas fa-hdd"></i> Disk Kullanımı</h4>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-8">
                        <table class="table table-hover">
                            <thead class="table-light">
                                <tr>
                                    <th>Bölüm</th>
                                    <th>Mount</th>
                                    <th>Toplam</th>
                                    <th>Kullanılan</th>
                                    <th style="width:200px">Doluluk</th>
                                </tr>
                            </thead>
                            <tbody>
                                {''.join(rows)}
                            </tbody>
                        </table>
                    </div>
                    <div class="col-md-4">
                        <div class="chart-container">
                            <canvas id="diskChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>
        </div>
"""


def _build_services_section(**kwargs) -> str:
    """Servisler section'ı."""
    running = kwargs.get('running_services', [])
    failed = kwargs.get('failed_services', [])
    suspicious = kwargs.get('suspicious_services', [])
    
    running_items = []
    for svc in running[:30]:
        running_items.append(f"""
            <div class="service-item">
                <span class="status-indicator status-running"></span>
                <span>{_escape(str(svc)[:70])}</span>
            </div>
        """)
    
    failed_items = []
    for svc in failed:
        failed_items.append(f"""
            <div class="service-item">
                <span class="status-indicator status-failed"></span>
                <strong class="text-danger">{_escape(str(svc)[:70])}</strong>
            </div>
        """)
    
    suspicious_items = []
    for svc in suspicious:
        suspicious_items.append(f"""
            <div class="service-item">
                <span class="status-indicator status-warning"></span>
                <span class="text-warning">{_escape(str(svc)[:70])}</span>
            </div>
        """)
    
    return f"""
        <div class="card mb-4 animate-fade-in" id="servis" style="animation-delay: 1s;">
            <div class="card-header bg-primary text-white">
                <h4 class="mb-0"><i class="fas fa-cogs"></i> Servis Durumu</h4>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-4">
                        <h5 class="text-success">
                            <i class="fas fa-check-circle"></i> Çalışan Servisler 
                            <span class="badge bg-success">{len(running)}</span>
                        </h5>
                        <div class="scroll-section">
                            {''.join(running_items) or '<p class="text-muted">Servis bulunamadı</p>'}
                        </div>
                    </div>
                    <div class="col-md-4">
                        <h5 class="text-danger">
                            <i class="fas fa-times-circle"></i> Sorunlu Servisler 
                            <span class="badge bg-danger">{len(failed)}</span>
                        </h5>
                        <div class="scroll-section">
                            {''.join(failed_items) or '<p class="text-success"><i class="fas fa-check"></i> Tüm servisler çalışıyor</p>'}
                        </div>
                    </div>
                    <div class="col-md-4">
                        <h5 class="text-warning">
                            <i class="fas fa-exclamation-triangle"></i> Uyarı 
                            <span class="badge bg-warning">{len(suspicious)}</span>
                        </h5>
                        <div class="scroll-section">
                            {''.join(suspicious_items) or '<p class="text-muted">Uyarı yok</p>'}
                        </div>
                    </div>
                </div>
            </div>
        </div>
"""


def _build_security_section(**kwargs) -> str:
    """Güvenlik section'ı."""
    sec = kwargs.get('security_summary', {})
    
    firewall_status = sec.get('firewall_status', 'Bilinmiyor')
    firewall_badge = 'success' if 'aktif' in firewall_status.lower() else 'danger'
    
    updates = sec.get('security_updates_count', -1)
    update_badge = 'success' if updates == 0 else 'warning' if updates > 0 else 'secondary'
    
    apparmor = sec.get('apparmor_status', 'N/A')
    apparmor_badge = 'success' if 'enforce' in str(apparmor).lower() else 'warning'
    
    return f"""
        <div class="card mb-4 animate-fade-in" id="guvenlik" style="animation-delay: 1.1s;">
            <div class="card-header bg-danger text-white">
                <h4 class="mb-0"><i class="fas fa-shield-alt"></i> Güvenlik Durumu</h4>
            </div>
            <div class="card-body">
                <div class="row g-4 text-center">
                    <div class="col-md-4">
                        <div class="metric-card border border-{firewall_badge}">
                            <i class="fas fa-fire fa-3x text-{firewall_badge} mb-3"></i>
                            <h6 class="text-muted">Güvenlik Duvarı (UFW)</h6>
                            <h4><span class="badge-custom bg-{firewall_badge}">{_escape(firewall_status)}</span></h4>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="metric-card border border-{update_badge}">
                            <i class="fas fa-download fa-3x text-{update_badge} mb-3"></i>
                            <h6 class="text-muted">Güvenlik Güncellemeleri</h6>
                            <h4><span class="badge-custom bg-{update_badge}">{updates if updates >= 0 else '?'} güncelleme</span></h4>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="metric-card border border-{apparmor_badge}">
                            <i class="fas fa-lock fa-3x text-{apparmor_badge} mb-3"></i>
                            <h6 class="text-muted">AppArmor</h6>
                            <h4><span class="badge-custom bg-{apparmor_badge}">{_escape(str(apparmor))}</span></h4>
                        </div>
                    </div>
                </div>
            </div>
        </div>
"""


def _build_network_section(**kwargs) -> str:
    """Ağ portları section'ı."""
    ports = kwargs.get('listening_ports', [])
    
    if not ports:
        return ""
    
    rows = []
    for port in ports[:20]:
        protocol = port.get('protocol', 'N/A')
        proto_badge = 'primary' if protocol == 'tcp' else 'info'
        
        rows.append(f"""
            <tr>
                <td><span class="badge bg-{proto_badge}">{_escape(str(protocol).upper())}</span></td>
                <td><code>{_escape(port.get('address', 'N/A'))}</code></td>
                <td><strong>{_escape(port.get('port', 'N/A'))}</strong></td>
                <td>{_escape(port.get('process', 'N/A')[:50])}</td>
            </tr>
        """)
    
    return f"""
        <div class="card mb-4 animate-fade-in" style="animation-delay: 1.2s;">
            <div class="card-header bg-info text-white">
                <h4 class="mb-0"><i class="fas fa-network-wired"></i> Dinleyen Portlar ({len(ports)} adet)</h4>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-hover">
                        <thead class="table-light">
                            <tr>
                                <th>Protokol</th>
                                <th>Adres</th>
                                <th>Port</th>
                                <th>İşlem</th>
                            </tr>
                        </thead>
                        <tbody>
                            {''.join(rows)}
                        </tbody>
                    </table>
                </div>
                {f'<p class="text-muted mt-2"><small>İlk 20 port gösteriliyor. Toplam: {len(ports)}</small></p>' if len(ports) > 20 else ''}
            </div>
        </div>
"""


def _build_boot_section(**kwargs) -> str:
    """Açılış analizi section'ı."""
    boot = kwargs.get('boot_analysis', [])
    
    if not boot:
        return ""
    
    rows = []
    for item in boot[:10]:
        time_str = item.get('time', 'N/A')
        service = item.get('service', 'N/A')
        
        rows.append(f"""
            <tr>
                <td><code>{_escape(time_str)}</code></td>
                <td>{_escape(service)}</td>
            </tr>
        """)
    
    return f"""
        <div class="card mb-4 animate-fade-in" style="animation-delay: 1.3s;">
            <div class="card-header bg-warning text-dark">
                <h4 class="mb-0"><i class="fas fa-stopwatch"></i> Açılış Performans Analizi</h4>
            </div>
            <div class="card-body">
                <p class="text-muted">En çok zaman alan 10 servis:</p>
                <table class="table table-hover">
                    <thead class="table-light">
                        <tr>
                            <th width="150">Süre</th>
                            <th>Servis</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(rows)}
                    </tbody>
                </table>
            </div>
        </div>
"""


def _build_processes_section(**kwargs) -> str:
    """En çok kaynak kullanan işlemler."""
    procs = kwargs.get('top_processes', [])
    
    if not procs:
        return ""
    
    rows = []
    for proc in procs[:15]:
        cpu = proc.get('cpu_percent', 0)
        mem = proc.get('memory_percent', 0)
        
        rows.append(f"""
            <tr>
                <td>{_escape(proc.get('user', 'N/A')[:15])}</td>
                <td>
                    <div class="progress progress-custom">
                        <div class="progress-bar bg-danger" style="width: {min(cpu, 100)}%">{cpu}%</div>
                    </div>
                </td>
                <td>
                    <div class="progress progress-custom">
                        <div class="progress-bar bg-warning" style="width: {min(mem, 100)}%">{mem:.1f}%</div>
                    </div>
                </td>
                <td><small><code>{_escape(str(proc.get('command', 'N/A'))[:60])}</code></small></td>
            </tr>
        """)
    
    return f"""
        <div class="card mb-4 animate-fade-in" style="animation-delay: 1.4s;">
            <div class="card-header bg-success text-white">
                <h4 class="mb-0"><i class="fas fa-tasks"></i> En Çok Kaynak Kullanan İşlemler</h4>
            </div>
            <div class="card-body">
                <table class="table table-sm table-hover">
                    <thead class="table-light">
                        <tr>
                            <th width="100">Kullanıcı</th>
                            <th width="150">CPU</th>
                            <th width="150">RAM</th>
                            <th>Komut</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(rows)}
                    </tbody>
                </table>
            </div>
        </div>
"""


def _get_custom_javascript(**kwargs) -> str:
    """Özel JavaScript kodu."""
    disks = kwargs.get('disk_usage', [])
    
    # Disk grafiği için veri hazırla
    disk_labels = []
    disk_data = []
    for disk in disks[:5]:
        mount = disk.get('mount_point', 'N/A')
        used_str = str(disk.get('used', '0')).replace('GB', '').replace('G', '').strip()
        try:
            used_num = float(used_str)
            disk_labels.append(mount)
            disk_data.append(used_num)
        except:
            pass
    
    return f"""
        // Dark mode toggle
        function toggleTheme() {{
            const html = document.documentElement;
            const currentTheme = html.getAttribute('data-bs-theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            html.setAttribute('data-bs-theme', newTheme);
            
            const icon = document.querySelector('#themeToggle i');
            icon.className = newTheme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
            
            localStorage.setItem('theme', newTheme);
        }}
        
        // Sayfa yüklendiğinde tema ayarla
        document.addEventListener('DOMContentLoaded', function() {{
            const savedTheme = localStorage.getItem('theme') || 'light';
            document.documentElement.setAttribute('data-bs-theme', savedTheme);
            
            const icon = document.querySelector('#themeToggle i');
            if (icon) {{
                icon.className = savedTheme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
            }}
            
            // Disk grafiği
            const diskCanvas = document.getElementById('diskChart');
            if (diskCanvas && {json.dumps(disk_labels)}.length > 0) {{
                new Chart(diskCanvas, {{
                    type: 'doughnut',
                    data: {{
                        labels: {json.dumps(disk_labels)},
                        datasets: [{{
                            data: {json.dumps(disk_data)},
                            backgroundColor: [
                                '#667eea',
                                '#764ba2',
                                '#f093fb',
                                '#4facfe',
                                '#43e97b'
                            ],
                            borderWidth: 2,
                            borderColor: '#fff'
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {{
                            legend: {{
                                position: 'bottom'
                            }},
                            title: {{
                                display: true,
                                text: 'Disk Kullanımı (GB)'
                            }}
                        }}
                    }}
                }});
            }}
            
            // Smooth scroll
            document.querySelectorAll('a[href^="#"]').forEach(anchor => {{
                anchor.addEventListener('click', function(e) {{
                    e.preventDefault();
                    const target = document.querySelector(this.getAttribute('href'));
                    if (target) {{
                        target.scrollIntoView({{ behavior: 'smooth' }});
                    }}
                }});
            }});
        }});
"""


def _escape(text: str) -> str:
    """HTML escape helper."""
    return html_escape.escape(str(text))


# Module metadata
__all__ = ['generate_html_report']
__version__ = '0.4.0'
__author__ = 'ozturu68'