import psutil
import time

def get_top_processes(count=10):
    """
    NİHAİ SÜRÜM 2.0: psutil'in önerdiği yöntemle DOĞRU CPU yüzdelerini hesaplar.
    """
    try:
        # Önce tüm işlemlerin bir listesini al, CPU yüzdelerini bir kez çağır (değerler 0 olacak)
        procs = [p for p in psutil.process_iter(['username', 'name', 'cmdline'])]
        for p in procs:
            p.cpu_percent()

        # Kısa bir süre bekle
        time.sleep(0.5)

        processes = []
        for p in procs:
            # İşlem hala çalışıyor mu kontrol et
            if not p.is_running():
                continue
            
            # Şimdi cpu_percent'i tekrar çağırarak gerçek değeri al
            cpu_usage = p.cpu_percent()
            mem_percent = p.memory_percent()
            
            cmdline = ' '.join(p.info['cmdline']) if p.info['cmdline'] else p.info['name']

            processes.append({
                'user': p.info['username'],
                'cpu': f"{cpu_usage:.1f}",
                'mem': f"{mem_percent:.1f}",
                'command': cmdline,
                'cpu_raw': cpu_usage
            })

    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass
    except Exception as e:
        return [{'user': 'HATA', 'cpu': '', 'mem': '', 'command': f"İşlemler listelenirken bir hata oluştu: {e}"}]

    sorted_processes = sorted(processes, key=lambda p: p['cpu_raw'], reverse=True)
    
    for proc in sorted_processes:
        del proc['cpu_raw']

    return sorted_processes[:count]