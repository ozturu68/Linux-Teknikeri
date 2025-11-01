# 🐧 Linux Teknikeri

<div align="center">

**Pop!_OS ve Debian tabanlı sistemler için kapsamlı sistem analiz ve bakım aracı**

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux-orange.svg)](https://www.linux.org/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

Sisteminizin sağlık durumunu analiz edin, performans sorunlarını tespit edin ve detaylı raporlar alın.

[Özellikler](#-özellikler) • [Kurulum](#-kurulum) • [Kullanım](#-kullanım) • [Örnek Çıktılar](#-örnek-çıktılar) • [Katkıda Bulunma](#-katkıda-bulunma)

</div>

---

## 📋 İçindekiler

- [Özellikler](#-özellikler)
- [Kurulum](#-kurulum)
- [Kullanım](#-kullanım)
- [Komut Satırı Seçenekleri](#-komut-satırı-seçenekleri)
- [Sistem Gereksinimleri](#-sistem-gereksinimleri)
- [Proje Yapısı](#-proje-yapısı)
- [Örnek Çıktılar](#-örnek-çıktılar)
- [Katkıda Bulunma](#-katkıda-bulunma)
- [Geliştirme Ortamı](#-geliştirme-ortamı)
- [Hata Bildirimi](#-hata-bildirimi)
- [Lisans](#-lisans)
- [Teşekkürler](#-teşekkürler)
- [Yazar](#-yazar)
- [Yol Haritası](#-yol-haritası)
- [İstatistikler](#-istatistikler)

---

## ✨ Özellikler

### 🖥️ Sistem Envanteri
- İşletim sistemi ve dağıtım bilgileri
- Kernel sürümü ve mimari
- Masaüstü ortamı tespiti (GNOME, KDE, XFCE)
- Hostname ve kritik sistem servisleri

### 🎮 GPU ve Sürücü Analizi
- NVIDIA: sürücü versiyonu, VRAM, CUDA compute capability
- Intel: Mesa/i915 durumu
- AMD: AMDGPU ve Mesa sürücü kontrolü
- OpenGL ve Vulkan API desteği
- Hibrit grafik (Optimus/PRIME) tespiti

### 💾 Disk ve Depolama
- Bölüm bazında disk kullanım analizi
- S.M.A.R.T. sağlık durumu kontrolü
- NVMe ve SATA disk desteği
- Büyük dosya tespiti
- Mount noktası analizi

### ⚙️ Servis ve Süreçler
- Aktif servislerin listesi (systemd)
- Başarısız/çökmüş servis tespiti
- Son 24 saatteki hata logları
- Açılış performans analizi (systemd-analyze)
- En çok kaynak kullanan süreçler

### 🔒 Güvenlik
- UFW güvenlik duvarı durumu
- AppArmor profil kontrolü
- Bekleyen güvenlik güncellemeleri
- Sudoers yapılandırması
- Son paket kurulum geçmişi

### 🌐 Ağ
- Dinleyen TCP/UDP portları
- Port–servis eşleştirmesi
- Ağ bağlantı durumu

### 📊 Raporlama
- HTML Rapor: Bootstrap 5 ve Chart.js ile modern, responsive tasarım
  - İnteraktif grafikler ve tablolar
  - Dark/Light mode
  - Yazdırılabilir (PDF export)
  - Mobil uyumlu
- JSON Export: API entegrasyonu için yapılandırılmış veri
- Konsol Raporu: Renkli ve okunabilir terminal çıktısı

### 🎯 Sağlık Skoru Sistemi
Sistem sağlığı 0–100 arasında değerlendirilir:
- Disk Sağlığı (30 puan): S.M.A.R.T. durumu, kullanım oranı
- Servisler (25 puan): Çalışan/çökmüş servis sayısı
- Güvenlik (25 puan): Güvenlik duvarı, güncellemeler
- Performans (20 puan): Kaynak kullanımı, açılış süresi

---

## 🚀 Kurulum

### Gereksinimler
- Python: 3.10 veya üzeri
- İşletim Sistemi: Linux (Ubuntu, Debian, Pop!_OS üzerinde test edilmiştir)
- Yetkiler: Bazı kontroller için `sudo` gerekebilir

### Adım 1 — Repository’yi klonlayın
```bash
git clone https://github.com/ozturu68/Linux-Teknikeri.git
cd Linux-Teknikeri
```

### Adım 2 — Sanal ortam oluşturun (önerilir)
```bash
python3 -m venv venv
source venv/bin/activate
```

### Adım 3 — Kurulum
```bash
pip install -e .
```

### Adım 4 — Bağımlılıklar
Kurulum sırasında otomatik yüklenir. Manuel yüklemek için:
```bash
pip install rich psutil
```

---

## 💻 Kullanım

### Temel kullanım
```bash
# Temel sistem analizi (konsol raporu)
linux-teknikeri

# Detaylı log ile çalıştırma
linux-teknikeri --verbose
```

### HTML rapor oluşturma
```bash
# Modern HTML rapor oluştur
linux-teknikeri --html sistem-raporu.html

# Raporu varsayılan tarayıcıda aç
xdg-open sistem-raporu.html
```

### JSON dışa aktarma
```bash
# Yapılandırılmış veri çıktısı
linux-teknikeri --json sistem-verileri.json

# JSON verisini biçimli görüntüle
python -m json.tool < sistem-verileri.json
```

### Tüm özellikleri birlikte kullanma
```bash
linux-teknikeri --html rapor.html --json veri.json --verbose
```

---

## 🧩 Komut Satırı Seçenekleri
```text
Kullanım: linux-teknikeri [OPTIONS]

Seçenekler:
  --html FILE      HTML formatında rapor oluştur
  --json FILE      JSON formatında veri dışa aktar
  --verbose, -v    Detaylı log çıktısı
  --version        Sürüm bilgisini göster
  --help           Yardım mesajını göster
```

---

## 📦 Sistem Gereksinimleri

### Python bağımlılıkları
```toml
rich   >= 13.0.0   # Terminal UI ve progress bar
psutil >= 5.9.0    # Sistem bilgileri ve süreç yönetimi
```

### Sistem araçları (opsiyonel)
Bu araçlar gelişmiş özellikler için gereklidir; yoksa ilgili kontroller atlanır:
- `nvidia-smi` — NVIDIA GPU analizi
- `glxinfo` — OpenGL bilgileri
- `vulkaninfo` — Vulkan desteği
- `smartctl` — S.M.A.R.T. disk kontrolü
- `ufw` — Güvenlik duvarı durumu
- `aa-status` — AppArmor profilleri

---

## 🧱 Proje Yapısı
```text
Linux-Teknikeri/
├── src/
│   └── linux_teknikeri/
│       ├── __init__.py             # Paket tanımı
│       ├── __main__.py             # Entry point
│       ├── main.py                 # Ana program mantığı
│       │
│       ├── checks/                 # Kontrol modülleri
│       │   ├── __init__.py
│       │   ├── check_drivers.py    # GPU sürücü analizi
│       │   ├── check_security.py   # Güvenlik kontrolleri
│       │   ├── check_services.py   # Servis yönetimi
│       │   └── check_storage.py    # Disk ve S.M.A.R.T.
│       │
│       ├── reporting/              # Rapor üreticiler
│       │   ├── __init__.py
│       │   ├── html_reporter.py    # Modern HTML rapor
│       │   └── reporter.py         # JSON ve konsol
│       │
│       └── utils/                  # Yardımcı araçlar
│           ├── __init__.py
│           └── command_runner.py   # Güvenli komut çalıştırıcı
│
├── pyproject.toml                  # Proje yapılandırması
├── README.md                       # Bu dosya
├── LICENSE                         # MIT Lisans
└── CHANGELOG.md                    # Sürüm notları
```

---

## 🎨 Örnek Çıktılar

### Konsol raporu
```text
======================================================================
                🐧 LINUX TEKNİKERİ - Kapsamlı Sistem Analizi
                          v0.4.0 | © 2025 ozturu68
======================================================================

✓ Sistem Bilgileri
  • İşletim Sistemi: Pop!_OS 22.04 LTS
  • Kernel: 6.16.3-76051603-generic
  • CPU: 12th Gen Intel(R) Core(TM) i5-12450H
  • RAM: 15.4 GB

✓ GPU Sürücüleri
  • NVIDIA GeForce RTX 3050 Mobile (Driver: 550.120)
  • Intel Alder Lake-P (Mesa 24.0.0)

✓ Disk Kullanımı
  • /dev/nvme0n1p1 → / (512 GB, %65 dolu)
  • S.M.A.R.T. Durumu: PASSED

✓ Servisler
  • Çalışan: 44 servis
  • Sorunlu: 0 servis

✓ Güvenlik
  • Güvenlik Duvarı: Aktif (UFW)
  • AppArmor: 35 profil enforce modda
  • Bekleyen Güncelleme: 0

╭───────────────────────── 📊 Özet ─────────────────────────╮
│           Sistem Sağlık Skoru: 80/100                     │
│                                                          │
│   💾 Disk Sağlığı:   25/30  ✅                            │
│   ⚙️  Servisler:      10/25  ⚠️                            │
│   🔒 Güvenlik:       25/25  ✅                            │
│   ⚡ Performans:     20/20  ✅                            │
╰──────────────────────────────────────────────────────────╯

✓ Analiz tamamlandı! (Toplam süre: 3.38s)
```

### HTML rapor özellikleri
- 📈 İnteraktif disk kullanım grafikleri
- 🔄 Servis durumu görünümü
- 🌓 Dark/Light mode
- 📱 Responsive tasarım
- 🖨️ Print-friendly (PDF export)
- 🎨 Bootstrap 5 ile modern UI
- 📊 Chart.js ile dinamik grafikler

---

## 🤝 Katkıda Bulunma

Katkılarınızı bekliyoruz! Lütfen şu adımları izleyin:

1. Fork edin: https://github.com/ozturu68/Linux-Teknikeri/fork  
2. Feature branch oluşturun:  
   ```bash
   git checkout -b feature/amazing-feature
   ```
3. Değişikliklerinizi commit edin:  
   ```bash
   git commit -m "feat: amazing feature"
   ```
4. Branch’i push edin:  
   ```bash
   git push origin feature/amazing-feature
   ```
5. Pull Request açın.

### Commit mesaj formatı (Conventional Commits)
```text
feat: yeni özellik ekle
fix: hata düzeltmesi
docs: dokümantasyon güncellemesi
style: kod formatı değişikliği
refactor: kod iyileştirmesi
test: test ekleme/düzeltme
chore: genel bakım işleri
```

---

## 🛠️ Geliştirme Ortamı
```bash
# Development modunda kurulum
pip install -e ".[dev]"

# Kod formatlama
black src/

# Linting
pylint src/linux_teknikeri/

# Type checking
mypy src/
```

---

## 🐛 Hata Bildirimi

Bir hata buldunuz mu? Lütfen Issue açın ve şu bilgileri ekleyin:
- İşletim sistemi ve versiyonu
- Python versiyonu
- Hata mesajı ve traceback
- Tekrar üretme adımları

---

## 📝 Lisans

Bu proje MIT Lisansı ile lisanslanmıştır. Detaylar için [LICENSE](LICENSE) dosyasına bakın.

---

## 🙏 Teşekkürler

Bu proje şu harika açık kaynak projelerden yararlanmaktadır:
- [Rich](https://github.com/Textualize/rich) — Terminal UI ve progress bar
- [psutil](https://github.com/giampaolo/psutil) — Sistem bilgileri
- [Bootstrap](https://getbootstrap.com/) — HTML rapor tasarımı
- [Chart.js](https://www.chartjs.org/) — İnteraktif grafikler
- [Font Awesome](https://fontawesome.com/) — İkonlar

---

## 👤 Yazar

- GitHub: [@ozturu68](https://github.com/ozturu68)  
- E-posta: ozturu68@users.noreply.github.com

---

## 🗺️ Yol Haritası

- [ ] PDF rapor desteği  
- [ ] E-posta bildirimleri  
- [ ] Otomatik sistem bakımı  
- [ ] Web arayüzü (Flask/FastAPI)  
- [ ] Docker container desteği  
- [ ] Fedora/Arch Linux desteği  
- [ ] Cron job entegrasyonu  
- [ ] Telegram bot bildirimleri  

---

## 📊 İstatistikler

![GitHub stars](https://img.shields.io/github/stars/ozturu68/Linux-Teknikeri?style=social)
![GitHub forks](https://img.shields.io/github/forks/ozturu68/Linux-Teknikeri?style=social)
![GitHub issues](https://img.shields.io/github/issues/ozturu68/Linux-Teknikeri)
![GitHub pull requests](https://img.shields.io/github/issues-pr/ozturu68/Linux-Teknikeri)
![GitHub last commit](https://img.shields.io/github/last-commit/ozturu68/Linux-Teknikeri)

<div align="center">

Made with ❤️ for the Linux community  
<a href="#-linux-teknikeri">⬆ Başa Dön</a>

</div>
