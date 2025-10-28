from utils.command_runner import run_command

def _get_services_by_state(state: str) -> list[str]:
    """
    Verilen duruma göre (örn: 'running', 'failed') servisleri listeleyen özel bir yardımcı fonksiyon.
    """
    command = ["systemctl", "list-units", "--type=service", f"--state={state}", "--no-legend", "--no-pager"]
    
    stdout, stderr, returncode = run_command(command)
    
    if returncode != 0:
        print(f"Uyarı: '{state}' durumundaki servisler listelenemedi. Hata: {stderr}")
        return []

    services = []
    lines = stdout.strip().splitlines()
    
    for line in lines:
        if not line.strip():
            continue

        parts = line.split()
        
        # Eğer satır boşluklara bölündükten sonra boşsa atla
        if not parts:
            continue

        # Düzeltilmiş mantık:
        # Eğer satır '●' ile başlıyorsa, servis adı ikinci elemandır (parts[1]).
        # Aksi halde, ilk elemandır (parts[0]).
        service_name = ""
        if parts[0] == '●':
            # Listenin en az iki elemanı olduğundan emin ol
            if len(parts) > 1:
                service_name = parts[1]
        else:
            service_name = parts[0]
        
        # Eğer bir servis adı bulduysak listeye ekle
        if service_name:
            services.append(service_name)
            
    return services

def get_running_services() -> list[str]:
    """Sistemde aktif olarak çalışan systemd servislerini listeler."""
    return _get_services_by_state("running")

def get_failed_services() -> list[str]:
    """Sistemde 'failed' durumundaki systemd servislerini listeler."""
    return _get_services_by_state("failed")