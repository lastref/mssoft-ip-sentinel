# MSSOFT IP Sentinel

MSSOFT IP Sentinel; FortiAnalyzer trafik kayıtları ve IPv4 listeleri için tasarlanmış, AbuseIPDB itibar verisini RIPEstat BGP prefix bilgisiyle birleştiren cross-platform masaüstü uygulamasıdır. Tekrarlanan adresleri tekilleştirir, yüksek riskli adresleri zaman damgalı bir rapor klasöründe saklar.

## Özellikler

- Windows, macOS ve Linux için tek Python kaynak tabanı.
- `.txt` ve `.log` girdileri; FortiAnalyzer `srcip` alanı bulunduğunda yalnızca bu alan taranır.
- Genel internete yönlendirilemeyen, multicast, loopback, link-local, reserved ve unspecified IPv4 adreslerini hariç tutar.
- Çoklu API anahtarı, işletim sistemi anahtar kasası ve günlük anahtar başına 1.000 **API isteği** kotası.
- Her HTTP denemesi (yeniden deneme ve hata dahil) kalıcı, atomik bir sayaçla rezerve edilir; kota/yetki hatasında aynı IP sıradaki anahtarla sürdürülür.
- Arka plan taraması, iptal düğmesi, sınırlı arayüz günlüğü ve denetlenebilir `audit.log`.
- RIPEstat BGP cevabı yoksa riskli IP kaybolmaz: özet dosyasına güvenli tek-adres subneti `IP/32` yazılır ve detay raporunda `host_32_fallback` olarak etiketlenir. Araç hiçbir zaman tahmini `/24` üretmez.

## Çıktılar

Her çalışma seçilen çıktı üst klasöründe `MSSOFT_IP_Sentinel_YYYY-MM-DD_HH-MM-SS` adlı yeni bir klasör oluşturur:

- `ozet_ipv4.txt`: Yalnızca `IP/prefix` satırları; IPv4 blok listesi olarak kullanılabilir.
- `detayli_rapor.csv`: Skor, rapor sayıları, ASN, subnet kaynağı, ISP, ülke ve anahtar etiketi dahil kayıtlar. CSV hücreleri formül/enjeksiyon karakterlerine karşı nötrleştirilir.
- `detayli_rapor.json`: Makine tarafından tüketilebilen ayrıntılı sonuçlar.
- `run.json`: Tarama özeti, API deneme sayaçları ve iptal durumu.
- `audit.log`: Hata ve işlem denetim günlüğü.

## Kurulum ve çalıştırma

Python 3.10 veya üzeri gerekir. Bağımlılıklar sabit sürümlere kilitlenmiştir.

```bash
python -m pip install -r requirements.txt
python app.py
```

Windows'ta `run_windows.bat`, macOS'ta `run_macos.command` dosyası kullanılabilir. Başlatıcılar eksik paket varsa ilk açılışta kurulum yapar; her açılışta ağdan paket indirmez. Linux'ta aynı şekilde terminalden yukarıdaki iki komut çalıştırılır.

Uygulama açıldığında **Ayarlar** sekmesinden her AbuseIPDB anahtarına ayrı bir etiket verin. Tarama devam ederken ayarlar kilitlenir; değişiklikler yalnızca sonraki taramaya uygulanır.

## Anahtar kasası ve gizlilik

API anahtarının kendisi proje, rapor ve günlük dosyalarına yazılmaz. Anahtar değerleri macOS Keychain, Windows Credential Manager veya Linux Secret Service/KWallet gibi işletim sistemi anahtar kasasında tutulur. Linux masaüstü ortamında uygun bir keyring backend yoksa uygulama anahtar kaydetmez ve kurulum uyarısı gösterir. Alternatif/yerel keyring backendleri kurum politikası açısından ayrıca değerlendirilmelidir.

Kota sayacı `~/.mssoft-ip-sentinel/api_usage.json` altında yalnızca anahtarın SHA-256 parmak izi ve güncel UTC günlük kullanım adedini tutar; anahtar metni içermez. Raporlardaki IP, ISP, ülke ve itibar verileri güvenlik verisi sayılabilir. Çıktı klasörünü, erişim yetkilerini ve kurumunuzun saklama politikasını buna göre yönetin.

AbuseIPDB ve RIPEstat sorguları ilgili servislerin uç noktalarına gönderilir. Bu ürün, bu servislerin erişilebilirliğine ve döndürdüğü verinin doğruluğuna bağımlıdır.

## Risk politikası

AbuseIPDB, antivirüs tespit sayısı yerine `abuseConfidenceScore` (0-100) sunar. Varsayılan eşik `25`tir. Daha muhafazakâr bir engelleme politikası için `50` ve üzeri bir eşik seçin; otomatik engelleme öncesi kurumun whitelist, değişiklik yönetimi ve etki analizi süreçlerini uygulayın.

## Paketleme gerçekliği

Bağımsız uygulama paketi her hedef işletim sisteminin kendi ortamında üretilmelidir; macOS üzerinde üretilen PyInstaller paketi Windows `.exe` olmaz. Örnekler:

```bash
# Windows
pyinstaller --noconsole --onedir --name "MSSOFT IP Sentinel" --add-data "assets;assets" app.py

# macOS / Linux
pyinstaller --noconsole --onedir --name "MSSOFT IP Sentinel" --add-data "assets:assets" app.py
```

Kaynak dağıtımı için `distribution_manifest.txt` ve `build_distribution.py` bulunur. Bu paket çalışma raporlarını, yerel ayarları, API anahtarlarını ve `.git` geçmişini dahil etmez.
