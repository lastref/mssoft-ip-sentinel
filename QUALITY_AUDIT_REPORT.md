# MSSOFT IP Sentinel — Kalite ve Kabul Raporu

Tarih: 20 Ağustos 2026
Durum: Kabul edildi

## İnceleme akışı

1. Güvenlik sertleştirmesi
2. Çalışma zamanı ve bellek optimizasyonu
3. GUI/UX incelemesi
4. Yönetici kabul incelemesi
5. Bağımsız veri bütünlüğü, güvenlik/yayın ve GUI/cross-platform denetimleri
6. Bulgu düzeltmeleri ve yeniden kabul

## Uygulanan kontroller

- API anahtarları yalnız işletim sistemi anahtar kasasında tutulur. Yerel indeks, anahtar değerini içermez; ayar dosyası izinleri kısıtlanır.
- Ağ istekleri sabit HTTPS uç noktalarına yönlendirilir; proxy ortamı devre dışıdır, yönlendirme kapalıdır ve zaman aşımı uygulanır.
- Anahtar kullanımı, anahtarın kendisi yerine SHA-256 parmak iziyle günlük ve atomik olarak sayılır. Her AbuseIPDB isteği, tekrar denemeleri de dahil, kotaya dahildir. 1.000 istekte bir sonraki anahtara geçilir.
- Büyük loglar parça parça okunur. 1 MiB parça sınırındaki IPv4 ve FortiAnalyzer `srcip` kayıtları için regresyon testleri uygulanmıştır.
- Multicast, private, CGNAT, loopback, reserved ve geçersiz IPv4 tokenları filtrelenir. Forti `srcip` alanı mevcutsa hedef IP'lere düşülmez.
- Yüksek riskli IP için RIPEstat prefix bilgisi alınamazsa özet kapsaması korunur; sonuç `IP/32` ve fallback durumu ile kaydedilir.
- CSV çıktısı formül, kontrol karakteri ve satır sonu enjeksiyonuna karşı nötrleştirilir.
- Arayüz tarama sırasında ayarları kilitler, iptal isteğini açıkça bildirir, olay kuyruğunu sınırlar ve sonuç klasörünü açabilir.
- Dağıtım ZIP'i manifest kontrollüdür; `.git`, bytecode, raporlar, anahtar ayarları, macOS meta dosyaları ve eski logo pakete girmez.

## Doğrulama özeti

- Python derleme denetimi: başarılı
- 1.001 IP bütünlük testi: başarılı
- 1 MiB sınırını aşan girdi testi: başarılı
- Sınırda Forti `srcip` testi: başarılı
- API anahtarı rotasyonu, 429 sonrası aynı IP tekrar denemesi ve kalıcı kota testi: başarılı
- RIPEstat başarısızlığı `/32` fallback testi: başarılı
- Temiz ZIP manifest ve gizli veri denetimi: başarılı
- Yönetici nihai kararı: kabul

## Bilinen platform notları

- Windows üzerinde canlı GUI ve PyInstaller paket testi bu macOS ortamında yürütülmedi. Kaynak kod ve Windows başlatıcısı hazırdır; yayın öncesi Windows smoke testi önerilir.
- Anahtar kasası güvenliği, hedef işletim sisteminde seçilen keyring backend'ine bağlıdır. Uygulama desteklenmeyen backend'i engeller, tanınmayan backend için uyarı verir.
