# MSSOFT IP Sentinel — Ekipler İçin IP Risk Değerlendirme

MSSOFT IP Sentinel; FortiAnalyzer trafik kayıtları ve IPv4 listeleri için tasarlanmış, AbuseIPDB itibar verisini RIPEstat BGP prefix bilgisiyle birleştiren cross-platform bir IP risk değerlendirme ürünüdür. Tekrarlanan adresleri tekilleştirir, yüksek riskli adresleri denetlenebilir raporlarla sunar ve güvenlik ekiplerinin hızlı ön değerlendirme yapmasını sağlar.

Masaüstü uygulamasına ek olarak ekipler için bir web portalı da içerir. Portal ham log dosyasını tarayıcıda işler; sadece tekilleştirilmiş genel IP’ler güvenli ekip geçidine gönderilir.

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

## Web portalı

Portal, GitHub Pages üzerinde müşteri ve ekip arayüzü olarak yayımlanır:

`https://lastref.github.io/mssoft-ip-sentinel/`

AbuseIPDB API v2, tarayıcıdan doğrudan çağrı için CORS desteği vermez ve API anahtarlarının istemci tarafında kullanılmamasını ister. Bu nedenle web portalı API anahtarı içermez. Tarama, Cloudflare Worker üzerinde çalışan güvenli API geçidi üzerinden yürür; anahtarlar yalnız Worker secret alanında tutulur.

Yayımlanmış portal, sade ve erişilebilir bir React çalışma alanıdır. React Bits `AnimatedContent` bileşeni, yalnız düşük hareketli bölüm geçişlerinde kullanılır; `prefers-reduced-motion` tercihi etkinse geçişler kapatılır. Geçit çoklu anahtar havuzunu kullanır, anahtar başına günlük 1.000 API isteği sınırını kalıcı olarak izler ve sınır ya da yetkilendirme hatasında sıradaki anahtara geçer.

Portal sonuçlarında iki blok listesi indirilebilir: BGP bilgisinden gelen `IP/prefix` özeti ve yalnız eşik üstü IP’leri `IP/32` biçiminde veren riskli ana makine listesi. İkinci seçenek, geniş servis sağlayıcı subnetlerini engellemeden tek adres bazlı kural oluşturmak içindir.

Portalda `.log` ve `.txt` dosyası seçmenin yanında, IPv4 adreslerini alt alta doğrudan yapıştırarak da tarama başlatabilirsiniz. API kullanım kartı, UTC günü için her anahtarın kullanılan ve kalan sorgu miktarını `API 1`, `API 2` biçiminde gösterir; anahtar metinleri hiçbir zaman portala iletilmez.

Web geliştirme ve yerel önizleme:

```bash
cd web
npm ci
npm run dev
```

Üretim derlemesi için `npm run build` çalıştırın. GitHub Pages iş akışı bu derlemeyi otomatik üretir ve yalnız `web/dist` içeriğini yayımlar.

Kurulum, ekip erişim politikası ve Cloudflare Access adımları için [WEB_DEPLOYMENT.md](WEB_DEPLOYMENT.md) belgesine bakın.

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

Web portalı üzerinden çalışırken ham log dosyası cihazda kalır. Geçide yalnız tekilleştirilmiş genel IP’ler, seçilen eşik ve rapor yaşı gönderilir. Worker’ı Cloudflare Access ile yalnız ekip üyelerine sınırlandırın; CORS tek başına erişim denetimi değildir.

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
