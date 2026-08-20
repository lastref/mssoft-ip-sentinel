# MSSOFT IP Sentinel Web Portal Dağıtımı

Bu kurulum GitHub Pages’i müşteri arayüzü, Cloudflare Worker’ı AbuseIPDB anahtarlarını güvenli tutan ekip geçidi olarak kullanır.

## Güvenlik modeli

```text
Ekip üyesi tarayıcısı
  └─ GitHub Pages portalı
       ├─ Logu cihazda tekilleştirir
       └─ Genel IP listesini gönderir
            └─ Cloudflare Access korumalı Worker
                 └─ Secret içindeki AbuseIPDB anahtarları
                      ├─ AbuseIPDB
                      └─ RIPEstat
```

GitHub Pages statik bir hizmettir. AbuseIPDB API v2 CORS başlığı vermediği ve anahtarların istemci tarafında bulunmaması gerektiği için tarayıcıdan doğrudan sorgu yapılmaz.

## GitHub Pages

`.github/workflows/deploy-pages.yml`, `main` dalındaki `web/` değişikliklerini yayımlar. Depo **Settings → Pages → Source** bölümünde **GitHub Actions** olarak yapılandırılmalıdır.

Yayın adresi: `https://lastref.github.io/mssoft-ip-sentinel/`

## Cloudflare Worker

Cloudflare hesabında oturum açtıktan sonra:

```bash
cd worker
npx wrangler login
npx wrangler secret put ABUSEIPDB_API_KEYS
npx wrangler deploy
```

`ABUSEIPDB_API_KEYS`, virgülle ayrılmış ekip anahtarlarından oluşur. Bu değer hiçbir zaman Git deposuna eklenmez. Worker, anahtar başına her AbuseIPDB isteğini günlük olarak sayar; 1.000 istekte sonraki anahtara geçer ve yetki/kota hatası alan anahtarı o gün devre dışı bırakır.

## Yalnız ekibe erişim

Worker yayımlandıktan sonra Cloudflare Zero Trust içinde bir **Access Application** oluşturun. Worker alan adını uygulama alanı olarak tanımlayın ve yalnız kurum e-posta alanı, onaylı e-posta listesi veya SSO grubunuz için izin politikası verin.

Bu katman zorunludur: Worker’daki CORS kontrolü bir tarayıcı kuralıdır, erişim denetimi değildir.

## Portalı bağlama

Portal, yayımlanmış MSSOFT Worker adresiyle hazır gelir. Gerekirse **Ayarları aç** düğmesinden kurumunuzun farklı HTTPS Worker adresini tanımlayabilirsiniz. Özel adres yalnız aktif tarayıcı oturumunda tutulur; portal API anahtarı istemez veya saklamaz.

## Operasyon notları

- Worker en fazla 50 IP’lik grupları işler; portal büyük listeleri otomatik gruplar.
- Ham log dosyası cihazda kalır; yalnız tekilleştirilmiş genel IP’ler geçide gider.
- RIPEstat prefixi bulunamazsa yüksek riskli IP `IP/32` olarak raporlanır.
- GitHub Pages arayüzünü değil API geçidini korur. Arayüzün de internete açık olmaması gerekiyorsa portalı kurum içi web barındırmasına taşıyın.
