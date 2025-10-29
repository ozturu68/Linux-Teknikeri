"""
HTML Rapor Üretici - Modern & İnteraktif
========================================

Bootstrap 5, Chart.js ve modern CSS ile profesyonel HTML raporları.

Features:
    - Responsive tasarım (mobil uyumlu)
    - İnteraktif grafikler (Chart.js)
    - Dark mode desteği
    - Print-friendly
    - Collapse/Expand sections
    - Export to PDF (tarayıcı ile)
    - Filtreleme ve arama

Author: ozturu68
Date: 2025-01-29
"""

from datetime import datetime
from typing import Dict, Any, List
import json
import html


def generate_html_report(data: Dict[str, Any], output_file: str) -> None:
    """
    Modern, interaktif HTML rapor üretir.
    
    Args:
        data: Sistem analiz verileri
        output_file: Çıktı dosya yolu
    """
    
    # HTML şablonu
    html_content = f"""<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Linux Teknikeri - Sistem Raporu</title>
    
    <!-- Bootstrap 5 CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    
    <!-- Font Awesome Icons -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    
    <!-- Chart.js -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    
    <style>
        :root {{
            --primary-color: #0d6efd;
            --success-color: #198754;
            --warning-color: #ffc107;
            --danger-color: #dc3545;
            --dark-bg: #1a1d23;
            --dark-card: #2d3139;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px 0;
        }}
        
        .main-container {{
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        
        .report-header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .report-header h1 {{
            font-size: 2.5rem;
            font-weight: bold;
            margin-bottom: 10px;
        }}
        
        .report-header .subtitle {{
            font-size: 1.1rem;
            opacity: 0.9;
        }}
        
        .health-score {{
            background: white;
            border-radius: 15px;
            padding: 30px;
            margin: -50px 30px 30px 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }}
        
        .score-circle {{
            width: 150px;
            height: 150px;
            border-radius: 50%;
            background: conic-gradient(
                var(--success-color) 0deg,
                var(--success-color) calc(var(--score) * 3.6deg),
                #e9ecef calc(var(--score) * 3.6deg),
                #e9ecef 360deg
            );
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto;
            position: relative;
        }}
        
        .score-circle::before {{
            content: '';
            position: absolute;
            width: 120px;
            height: 120px;
            background: white;
            border-radius: 50%;
        }}
        
        .score-text {{
            position: relative;
            z-index: 1;
            font-size: 2.5rem;
            font-weight: bold;
            color: var(--success-color);
        }}
        
        .section-card {{
            background: white;
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
            border-left: 4px solid var(--primary-color);
            transition: transform 0.3s, box-shadow 0.3s;
        }}
        
        .section-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(0,0,0,0.15);
        }}
        
        .section-title {{
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 20px;
            color: #2d3139;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .section-title i {{
            color: var(--primary-color);
        }}
        
        .info-table {{
            width: 100%;
        }}
        
        .info-table tr {{
            border-bottom: 1px solid #e9ecef;
        }}
        
        .info-table td {{
            padding: 12px 8px;
        }}
        
        .info-table td:first-child {{
            font-weight: 600;
            color: #6c757d;
            width: 200px;
        }}
        
        .badge-custom {{
            padding: 6px 12px;
            border-radius: 20px;
            font-weight: 500;
            font-size: 0.85rem;
        }}
        
        .badge-success {{ background: var(--success-color); color: white; }}
        .badge-warning {{ background: var(--warning-color); color: #000; }}
        .badge-danger {{ background: var(--danger-color); color: white; }}
        
        .progress-custom {{
            height: 25px;
            border-radius: 10px;
            background: #e9ecef;
        }}
        
        .progress-bar-custom {{
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
            font-size: 0.85rem;
        }}
        
        .chart-container {{
            position: relative;
            height: 300px;
            margin: 20px 0;
        }}
        
        .service-list {{
            max-height: 400px;
            overflow-y: auto;
        }}
        
        .service-item {{
            display: flex;
            align-items: center;
            padding: 10px;
            border-bottom: 1px solid #e9ecef;
        }}
        
        .service-item:last-child {{
            border-bottom: none;
        }}
        
        .service-status {{
            width: 10px;
            height: 10px;
            border-radius: 50%;
            margin-right: 10px;
        }}
        
        .status-running {{ background: var(--success-color); }}
        .status-failed {{ background: var(--danger-color); }}
        .status-warning {{ background: var(--warning-color); }}
        
        .footer {{
            text-align: center;
            padding: 30px;
            color: #6c757d;
            font-size: 0.9rem;
        }}
        
        @media print {{
            body {{
                background: white;
            }}
            
            .main-container {{
                box-shadow: none;
            }}
            
            .section-card {{
                page-break-inside: avoid;
            }}
        }}
        
        /* Dark Mode */
        .dark-mode {{
            background: var(--dark-bg);
            color: white;
        }}
        
        .dark-mode .main-container {{
            background: var(--dark-card);
        }}
        
        .dark-mode .section-card {{
            background: #3a3f4b;
            color: white;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="main-container">
            <!-- Header -->
            <div class="report-header">
                <h1><i class="fas fa-linux"></i> Linux Teknikeri</h1>
                <div class="subtitle">Kapsamlı Sistem Analiz Raporu</div>
                <div class="mt-3">
                    <small>Tarih: {datetime.now().strftime('%d %B %Y, %H:%M:%S')}</small>
                </div>
            </div>
            
            <!-- Sağlık Skoru -->
            <div class="health-score">
                <div class="row align-items-center">
                    <div class="col-md-4 text-center">
                        <div class="score-circle" style="--score: {data.get('health_score', 0)}">
                            <div class="score-text">{data.get('health_score', 0)}</div>
                        </div>
                        <h4 class="mt-3">Sistem Sağlık Skoru</h4>
                    </div>
                    <div class="col-md-8">
                        <div class="row">
                            {_generate_health_metrics(data)}
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Content -->
            <div class="p-4">
                <!-- Sistem Bilgileri -->
                {_generate_system_section(data)}
                
                <!-- Donanım -->
                {_generate_hardware_section(data)}
                
                <!-- GPU Sürücüleri -->
                {_generate_gpu_section(data)}
                
                <!-- Disk Analizi -->
                {_generate_disk_section(data)}
                
                <!-- Servisler -->
                {_generate_services_section(data)}
                
                <!-- Güvenlik -->
                {_generate_security_section(data)}
                
                <!-- Ağ Portları -->
                {_generate_network_section(data)}
            </div>
            
            <!-- Footer -->
            <div class="footer">
                <p>Linux Teknikeri v0.4.0 | © 2025 ozturu68</p>
                <p>
                    <a href="https://github.com/ozturu68/Linux-Teknikeri" target="_blank">
                        <i class="fab fa-github"></i> GitHub
                    </a>
                </p>
            </div>
        </div>
    </div>
    
    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    
    <!-- Custom JS -->
    <script>
        // Disk kullanım grafiği
        const diskData = {json.dumps(_prepare_disk_chart_data(data))};
        
        if (diskData.labels.length > 0) {{
            const ctx = document.getElementById('diskChart');
            if (ctx) {{
                new Chart(ctx, {{
                    type: 'doughnut',
                    data: {{
                        labels: diskData.labels,
                        datasets: [{{
                            data: diskData.data,
                            backgroundColor: [
                                '#0d6efd',
                                '#198754',
                                '#ffc107',
                                '#dc3545',
                                '#6c757d'
                            ]
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {{
                            legend: {{
                                position: 'bottom'
                            }}
                        }}
                    }}
                }});
            }}
        }}
        
        // Print fonksiyonu
        function printReport() {{
            window.print();
        }}
    </script>
</body>
</html>"""
    
    # Dosyaya yaz
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)


# Helper fonksiyonlar
def _generate_health_metrics(data: Dict[str, Any]) -> str:
    """Sağlık metrikleri HTML'i üretir."""
    metrics = [
        ("Disk Sağlığı", data.get('disk_health_score', 0), 30),
        ("Servisler", data.get('services_score', 0), 25),
        ("Güvenlik", data.get('security_score', 0), 25),
        ("Performans", data.get('performance_score', 0), 20)
    ]
    
    html_parts = []
    for name, score, max_score in metrics:
        percentage = (score / max_score) * 100 if max_score > 0 else 0
        color = "success" if percentage >= 80 else "warning" if percentage >= 50 else "danger"
        
        html_parts.append(f"""
        <div class="col-6 mb-3">
            <small class="text-muted">{name}</small>
            <div class="progress-custom">
                <div class="progress-bar-custom bg-{color}" style="width: {percentage}%">
                    {score}/{max_score}
                </div>
            </div>
        </div>
        """)
    
    return ''.join(html_parts)


def _generate_system_section(data: Dict[str, Any]) -> str:
    """Sistem bilgileri section'ı."""
    system = data.get('system_info', {})
    
    return f"""
    <div class="section-card">
        <div class="section-title">
            <i class="fas fa-desktop"></i> Sistem Bilgileri
        </div>
        <table class="info-table">
            <tr>
                <td>İşletim Sistemi</td>
                <td><strong>{html.escape(system.get('os_version', 'N/A'))}</strong></td>
            </tr>
            <tr>
                <td>Kernel</td>
                <td><code>{html.escape(system.get('kernel_version', 'N/A'))}</code></td>
            </tr>
            <tr>
                <td>Masaüstü Ortamı</td>
                <td>{html.escape(system.get('desktop_environment', 'N/A'))}</td>
            </tr>
            <tr>
                <td>Hostname</td>
                <td>{html.escape(system.get('hostname', 'N/A'))}</td>
            </tr>
        </table>
    </div>
    """


def _generate_hardware_section(data: Dict[str, Any]) -> str:
    """Donanım section'ı."""
    hw = data.get('hardware_info', {})
    
    return f"""
    <div class="section-card">
        <div class="section-title">
            <i class="fas fa-microchip"></i> Donanım
        </div>
        <table class="info-table">
            <tr>
                <td>İşlemci (CPU)</td>
                <td><strong>{html.escape(hw.get('cpu_model', 'N/A'))}</strong></td>
            </tr>
            <tr>
                <td>Bellek (RAM)</td>
                <td><strong>{html.escape(hw.get('total_ram', 'N/A'))}</strong></td>
            </tr>
            <tr>
                <td>Ekran Kartı</td>
                <td>{html.escape(hw.get('gpu_model', 'N/A'))}</td>
            </tr>
        </table>
    </div>
    """


def _generate_gpu_section(data: Dict[str, Any]) -> str:
    """GPU sürücü section'ı."""
    gpus = data.get('gpu_drivers', [])
    
    if not gpus:
        return ""
    
    rows = []
    for gpu in gpus:
        status_badge = "success" if "nvidia" in gpu.get('driver', '').lower() else "warning"
        rows.append(f"""
        <tr>
            <td>{html.escape(gpu.get('model', 'N/A'))}</td>
            <td><span class="badge-custom badge-{status_badge}">{html.escape(gpu.get('driver', 'N/A'))}</span></td>
            <td>{html.escape(gpu.get('driver_version', 'N/A'))}</td>
        </tr>
        """)
    
    return f"""
    <div class="section-card">
        <div class="section-title">
            <i class="fas fa-video"></i> GPU Sürücüleri
        </div>
        <table class="table table-hover">
            <thead>
                <tr>
                    <th>Model</th>
                    <th>Sürücü</th>
                    <th>Versiyon</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows)}
            </tbody>
        </table>
    </div>
    """


def _generate_disk_section(data: Dict[str, Any]) -> str:
    """Disk analizi section'ı."""
    disks = data.get('disk_usage', [])
    
    rows = []
    for disk in disks:
        usage = float(disk.get('usage_percent', 0))
        color = "danger" if usage >= 90 else "warning" if usage >= 70 else "success"
        
        rows.append(f"""
        <tr>
            <td><code>{html.escape(disk.get('partition', 'N/A'))}</code></td>
            <td>{html.escape(disk.get('mount_point', 'N/A'))}</td>
            <td>{html.escape(disk.get('total', 'N/A'))}</td>
            <td>
                <div class="progress-custom">
                    <div class="progress-bar-custom bg-{color}" style="width: {usage}%">
                        {usage:.1f}%
                    </div>
                </div>
            </td>
        </tr>
        """)
    
    return f"""
    <div class="section-card">
        <div class="section-title">
            <i class="fas fa-hdd"></i> Disk Kullanımı
        </div>
        <div class="row">
            <div class="col-md-6">
                <table class="table table-sm">
                    <thead>
                        <tr>
                            <th>Bölüm</th>
                            <th>Mount</th>
                            <th>Boyut</th>
                            <th>Doluluk</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(rows)}
                    </tbody>
                </table>
            </div>
            <div class="col-md-6">
                <div class="chart-container">
                    <canvas id="diskChart"></canvas>
                </div>
            </div>
        </div>
    </div>
    """


def _generate_services_section(data: Dict[str, Any]) -> str:
    """Servisler section'ı."""
    services = data.get('running_services', [])
    failed = data.get('failed_services', [])
    
    service_items = []
    for svc in services[:20]:  # İlk 20
        service_items.append(f"""
        <div class="service-item">
            <div class="service-status status-running"></div>
            <div>{html.escape(svc)}</div>
        </div>
        """)
    
    failed_items = []
    for svc in failed:
        failed_items.append(f"""
        <div class="service-item">
            <div class="service-status status-failed"></div>
            <div><strong>{html.escape(svc)}</strong></div>
        </div>
        """)
    
    return f"""
    <div class="section-card">
        <div class="section-title">
            <i class="fas fa-cogs"></i> Servis Durumu
        </div>
        <div class="row">
            <div class="col-md-6">
                <h6>Çalışan Servisler ({len(services)})</h6>
                <div class="service-list">
                    {''.join(service_items)}
                </div>
            </div>
            <div class="col-md-6">
                <h6>Sorunlu Servisler ({len(failed)})</h6>
                <div class="service-list">
                    {''.join(failed_items) if failed_items else '<p class="text-success"><i class="fas fa-check-circle"></i> Tüm servisler çalışıyor</p>'}
                </div>
            </div>
        </div>
    </div>
    """


def _generate_security_section(data: Dict[str, Any]) -> str:
    """Güvenlik section'ı."""
    security = data.get('security_summary', {})
    
    firewall_status = security.get('firewall_status', 'Bilinmiyor')
    firewall_badge = "success" if "Aktif" in firewall_status else "danger"
    
    updates = security.get('security_updates_count', -1)
    update_badge = "success" if updates == 0 else "warning" if updates > 0 else "secondary"
    
    return f"""
    <div class="section-card">
        <div class="section-title">
            <i class="fas fa-shield-alt"></i> Güvenlik
        </div>
        <div class="row">
            <div class="col-md-4 text-center mb-3">
                <h6>Güvenlik Duvarı</h6>
                <span class="badge-custom badge-{firewall_badge}">{html.escape(firewall_status)}</span>
            </div>
            <div class="col-md-4 text-center mb-3">
                <h6>Güvenlik Güncellemeleri</h6>
                <span class="badge-custom badge-{update_badge}">
                    {updates if updates >= 0 else 'N/A'} güncelleme
                </span>
            </div>
            <div class="col-md-4 text-center mb-3">
                <h6>AppArmor</h6>
                <span class="badge-custom badge-success">{html.escape(security.get('apparmor_status', 'N/A'))}</span>
            </div>
        </div>
    </div>
    """


def _generate_network_section(data: Dict[str, Any]) -> str:
    """Ağ portları section'ı."""
    ports = data.get('listening_ports', [])
    
    rows = []
    for port in ports[:15]:  # İlk 15
        rows.append(f"""
        <tr>
            <td><span class="badge bg-secondary">{html.escape(port.get('protocol', 'N/A'))}</span></td>
            <td><code>{html.escape(port.get('address', 'N/A'))}</code></td>
            <td><strong>{html.escape(port.get('port', 'N/A'))}</strong></td>
            <td>{html.escape(port.get('process', 'N/A'))}</td>
        </tr>
        """)
    
    return f"""
    <div class="section-card">
        <div class="section-title">
            <i class="fas fa-network-wired"></i> Dinleyen Portlar ({len(ports)} adet)
        </div>
        <table class="table table-sm table-hover">
            <thead>
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
    """


def _prepare_disk_chart_data(data: Dict[str, Any]) -> Dict[str, List]:
    """Disk grafiği için veri hazırlar."""
    disks = data.get('disk_usage', [])
    
    labels = []
    values = []
    
    for disk in disks[:5]:  # İlk 5 disk
        mount = disk.get('mount_point', 'N/A')
        used_gb = disk.get('used', '0').replace('GB', '').strip()
        
        try:
            used_num = float(used_gb)
            labels.append(mount)
            values.append(used_num)
        except:
            pass
    
    return {"labels": labels, "data": values}