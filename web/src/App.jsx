import { useMemo, useRef, useState } from "react";
import AnimatedContent from "./components/AnimatedContent";
import brandMark from "../assets/mssoft_ip_sentinel_logo_minimal.png";

const MAX_FILE_BYTES = 100 * 1024 * 1024;
// Worker alt istek sınırının altında kalmak için Worker ile aynı grup boyutu.
const BATCH_SIZE = 8;
const GATEWAY_KEY = "mssoft-ip-sentinel-gateway";
const DEFAULT_GATEWAY = "https://mssoft-ip-sentinel-gateway.mustafa-satiroglu.workers.dev";
const IP_PATTERN = /(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])/g;

function numericIp(ip) {
  return ip.split(".").reduce((total, value, index) => total + Number(value) * 256 ** (3 - index), 0);
}

function isRoutable(ip) {
  const [first, second] = ip.split(".").map(Number);
  if (first === 0 || first === 10 || first === 127 || first >= 224 || first >= 240) return false;
  if (first === 100 && second >= 64 && second <= 127) return false;
  if (first === 169 && second === 254) return false;
  if (first === 172 && second >= 16 && second <= 31) return false;
  if (first === 192 && (second === 0 || second === 168)) return false;
  if (first === 198 && (second === 18 || second === 19 || second === 51)) return false;
  if (first === 203 && second === 0) return false;
  return true;
}

function extractIps(text) {
  const candidates = text.match(IP_PATTERN)?.filter(isRoutable) ?? [];
  const unique = [...new Set(candidates)].sort((first, second) => numericIp(first) - numericIp(second));
  return { unique, duplicateCount: candidates.length - unique.length };
}

function formatNumber(value) {
  return Number(value || 0).toLocaleString("tr-TR");
}

function download(filename, content, type) {
  const blob = new Blob([content], { type });
  const address = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = address;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(address);
}

function riskHostsAs32(findings) {
  return [...new Set(findings.map((item) => item.ip).filter(Boolean))]
    .sort((first, second) => numericIp(first) - numericIp(second))
    .map((ip) => `${ip}/32`)
    .join("\n");
}

function Icon({ name, size = 18 }) {
  const paths = {
    document: <><path d="M6 2.75h7l3 3V21.25H6z" /><path d="M13 2.75v3h3M8.5 10h5M8.5 14h5M8.5 18h3.5" /></>,
    settings: <><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.7 1.7 0 0 0 .34 1.88l.06.06-2.07 2.07-.06-.06a1.7 1.7 0 0 0-1.88-.34 1.7 1.7 0 0 0-1.04 1.56V20.3h-2.93v-.13A1.7 1.7 0 0 0 10.78 18.6a1.7 1.7 0 0 0-1.88.34l-.06.06-2.07-2.07.06-.06A1.7 1.7 0 0 0 7.17 15a1.7 1.7 0 0 0-1.56-1.04h-.13v-2.93h.13A1.7 1.7 0 0 0 7.17 10a1.7 1.7 0 0 0-.34-1.88l-.06-.06L8.84 6l.06.06a1.7 1.7 0 0 0 1.88.34 1.7 1.7 0 0 0 1.04-1.56v-.13h2.93v.13A1.7 1.7 0 0 0 15.8 6.4a1.7 1.7 0 0 0 1.88-.34l.06-.06 2.07 2.07-.06.06A1.7 1.7 0 0 0 19.4 10a1.7 1.7 0 0 0 1.56 1.04h.13v2.93h-.13A1.7 1.7 0 0 0 19.4 15Z" /></>,
    play: <path d="m8 5 11 7-11 7Z" />,
    stop: <path d="M7 7h10v10H7z" />,
    download: <><path d="M12 3v12M7.5 10.5 12 15l4.5-4.5M5 20.5h14" /></>,
    chevron: <path d="m9 18 6-6-6-6" />,
  };
  return <svg className="icon" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name]}</svg>;
}

function App() {
  const inputRef = useRef(null);
  const controllerRef = useRef(null);
  const [ips, setIps] = useState([]);
  const [fileName, setFileName] = useState("");
  const [duplicateCount, setDuplicateCount] = useState(0);
  const [score, setScore] = useState(25);
  const [days, setDays] = useState(90);
  const [findings, setFindings] = useState([]);
  const [scanned, setScanned] = useState(0);
  const [running, setRunning] = useState(false);
  const [cancelled, setCancelled] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [gatewayDraft, setGatewayDraft] = useState(() => sessionStorage.getItem(GATEWAY_KEY) || DEFAULT_GATEWAY);
  const [gateway, setGateway] = useState(() => sessionStorage.getItem(GATEWAY_KEY) || DEFAULT_GATEWAY);
  const [gatewayError, setGatewayError] = useState("");
  const [status, setStatus] = useState({ tone: "ready", title: "Hazır", message: "Bir .log veya .txt dosyası seçerek başlayın." });
  const [dragActive, setDragActive] = useState(false);

  const progress = useMemo(() => ips.length ? Math.min(100, Math.round((scanned / ips.length) * 100)) : 0, [ips.length, scanned]);
  const canStart = Boolean(ips.length && gateway && !running);

  async function loadFile(file) {
    if (!file) return;
    if (file.size > MAX_FILE_BYTES) {
      setStatus({ tone: "error", title: "Dosya işlenemedi", message: "100 MB sınırını aşan dosyalar işlenmez." });
      return;
    }
    try {
      const text = await file.text();
      const extracted = extractIps(text);
      setIps(extracted.unique);
      setDuplicateCount(extracted.duplicateCount);
      setFileName(file.name);
      setFindings([]);
      setScanned(0);
      setCancelled(false);
      setStatus(extracted.unique.length
        ? { tone: "ready", title: "Girdi hazır", message: `${formatNumber(extracted.unique.length)} benzersiz genel IPv4 bulundu. Ham dosya tarayıcınızda kalır.` }
        : { tone: "error", title: "Genel IPv4 bulunamadı", message: "Dosyada taranabilecek genel IPv4 adresi yok." });
    } catch {
      setStatus({ tone: "error", title: "Dosya okunamadı", message: "Dosyayı okumak için tarayıcı izni veya geçerli bir metin dosyası gerekir." });
    }
  }

  async function handleSelection(event) {
    await loadFile(event.target.files?.[0]);
    event.target.value = "";
  }

  function saveGateway() {
    try {
      const url = new URL(gatewayDraft.trim());
      if (url.protocol !== "https:") throw new Error("HTTPS gerekli");
      const address = url.href.replace(/\/$/, "");
      sessionStorage.setItem(GATEWAY_KEY, address);
      setGateway(address);
      setGatewayError("");
      setSettingsOpen(false);
      setStatus({ tone: "ready", title: "Geçit kaydedildi", message: "Geçit adresi yalnız bu tarayıcı oturumunda saklanır." });
    } catch {
      setGatewayError("Geçerli bir HTTPS geçit adresi girin.");
    }
  }

  function cancelScan() {
    setCancelled(true);
    controllerRef.current?.abort();
    setStatus({ tone: "active", title: "İptal isteniyor", message: "Geçerli istek sonlandırılıyor; tamamlanan sonuçlar korunacak." });
  }

  async function startScan() {
    const parsedScore = Number(score);
    const parsedDays = Number(days);
    if (!Number.isInteger(parsedScore) || parsedScore < 0 || parsedScore > 100 || !Number.isInteger(parsedDays) || parsedDays < 1 || parsedDays > 365) {
      setStatus({ tone: "error", title: "Tarama ayarı geçersiz", message: "Risk skoru 0–100, rapor yaşı 1–365 arasında olmalıdır." });
      return;
    }

    const controller = new AbortController();
    controllerRef.current = controller;
    setRunning(true);
    setCancelled(false);
    setFindings([]);
    setScanned(0);
    setStatus({ tone: "active", title: "Tarama sürüyor", message: "Benzersiz genel IPv4 adresleri ekip geçidine gruplar halinde gönderiliyor." });
    let completed = 0;
    const collected = [];

    try {
      for (let index = 0; index < ips.length; index += BATCH_SIZE) {
        if (controller.signal.aborted) break;
        const response = await fetch(`${gateway}/api/scan`, {
          method: "POST",
          signal: controller.signal,
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ ips: ips.slice(index, index + BATCH_SIZE), score: parsedScore, maxAgeInDays: parsedDays }),
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(payload.error || `Geçit HTTP ${response.status} yanıtı verdi.`);
        const nextFindings = payload.findings || [];
        collected.push(...nextFindings);
        completed += payload.scanned ?? Math.min(BATCH_SIZE, ips.length - index);
        setFindings([...collected]);
        setScanned(completed);
      }
      setStatus(controller.signal.aborted
        ? { tone: "ready", title: "Tarama iptal edildi", message: `${formatNumber(completed)} IP işlendi; sonuçlar indirilebilir.` }
        : { tone: "success", title: "Tarama tamamlandı", message: `${formatNumber(completed)} IP işlendi, ${formatNumber(collected.length)} eşik üstü kayıt bulundu.` });
    } catch (error) {
      if (error.name !== "AbortError") {
        setStatus({ tone: "error", title: "Tarama durdu", message: error.message || "Geçide erişilemedi. Ekip erişimini ve geçit adresini kontrol edin." });
      }
    } finally {
      setRunning(false);
      controllerRef.current = null;
    }
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <a className="brand" href="#top" aria-label="MSSOFT IP Sentinel ana sayfa">
          <img src={brandMark} alt="MSSOFT" />
          <span className="brand-copy"><strong>MSSOFT</strong><span>IP Sentinel</span></span>
        </a>
        <div className="header-actions">
          <span className="team-label">Ekip çalışma alanı</span>
          <button className="icon-button" type="button" onClick={() => { setGatewayDraft(gateway); setGatewayError(""); setSettingsOpen(true); }} aria-label="Geçit ayarlarını aç"><Icon name="settings" /></button>
        </div>
      </header>

      <main id="top">
        <AnimatedContent distance={14} duration={0.38}>
          <section className="intro" aria-labelledby="page-title">
            <p className="section-label">IP RİSK DEĞERLENDİRME</p>
            <h1 id="page-title">Ağ kayıtlarındaki IP adreslerini düzenleyin ve değerlendirin.</h1>
            <p>Log veya IPv4 listesini seçin. Tekrarlanan kayıtlar cihazınızda ayıklanır; yalnızca genel IP adresleri kurum geçidine gönderilir.</p>
          </section>
        </AnimatedContent>

        <AnimatedContent distance={18} duration={0.42} delay={0.05}>
          <section className="workflow" aria-label="Tarama çalışma alanı">
            <article className="card source-card">
              <div className="card-heading">
                <div><p className="section-label">01 / GİRDİ</p><h2>Log veya IP listesi</h2></div>
                <span className="subtle-tag">Yerel işleme</span>
              </div>
              <label
                className={`file-drop ${dragActive ? "is-dragging" : ""}`}
                onDragEnter={(event) => { event.preventDefault(); setDragActive(true); }}
                onDragOver={(event) => event.preventDefault()}
                onDragLeave={() => setDragActive(false)}
                onDrop={(event) => { event.preventDefault(); setDragActive(false); loadFile(event.dataTransfer.files?.[0]); }}
              >
                <input ref={inputRef} type="file" accept=".log,.txt,text/plain" onChange={handleSelection} />
                <span className="file-icon"><Icon name="document" size={23} /></span>
                <strong>{fileName || "Bir .log veya .txt dosyası seçin"}</strong>
                <span>{fileName ? "Başka bir dosya seçmek için tıklayın" : "Maksimum 100 MB · Dosya cihazınızdan yüklenmez"}</span>
              </label>
              <div className="stat-grid" aria-live="polite">
                <div><span>Genel IPv4</span><strong>{formatNumber(ips.length)}</strong></div>
                <div><span>Yinelenen kayıt</span><strong>{formatNumber(duplicateCount)}</strong></div>
              </div>
            </article>

            <article className="card policy-card">
              <div className="card-heading"><div><p className="section-label">02 / POLİTİKA</p><h2>Tarama ayarları</h2></div></div>
              <div className="form-grid">
                <label>Minimum risk skoru<input type="number" min="0" max="100" value={score} onChange={(event) => setScore(event.target.value)} /></label>
                <label>Rapor yaşı (gün)<input type="number" min="1" max="365" value={days} onChange={(event) => setDays(event.target.value)} /></label>
              </div>
              <p className="field-note">Eşik üstündeki IP’ler detay raporuna eklenir. Özet dosyası yalnızca <code>IP/prefix</code> satırlarından oluşur.</p>
              <div className="button-row">
                <button className="button button-primary" type="button" disabled={!canStart} onClick={startScan}><Icon name="play" />Taramayı başlat</button>
                <button className="button button-secondary" type="button" disabled={!running} onClick={cancelScan}><Icon name="stop" />İptal et</button>
              </div>
            </article>
          </section>
        </AnimatedContent>

        <AnimatedContent distance={16} duration={0.4} delay={0.08}>
          <section className="status-card" aria-live="polite">
            <div className="status-top">
              <span className={`status-marker ${status.tone}`} aria-hidden="true" />
              <div><strong>{status.title}</strong><p>{status.message}</p></div>
              <span className="progress-value">{formatNumber(scanned)} / {formatNumber(ips.length)}</span>
            </div>
            <div className="progress-track" aria-label={`İlerleme: yüzde ${progress}`}><span style={{ width: `${progress}%` }} /></div>
          </section>
        </AnimatedContent>

        {(findings.length > 0 || scanned > 0 || cancelled) && (
          <AnimatedContent distance={20} duration={0.42}>
            <section className="results-section" aria-labelledby="results-title">
              <div className="results-heading">
                <div><p className="section-label">03 / SONUÇ</p><h2 id="results-title">Risk değerlendirme kayıtları</h2></div>
                <div className="download-row">
                  <button className="button button-secondary compact" type="button" onClick={() => download("mssoft-ip-sentinel-ip-prefix.txt", findings.map((item) => item.ip_with_prefix).join("\n") + (findings.length ? "\n" : ""), "text/plain;charset=utf-8")}><Icon name="download" />IP/prefix özeti</button>
                  <button className="button button-secondary compact" type="button" onClick={() => { const hosts = riskHostsAs32(findings); download("mssoft-ip-sentinel-riskli-ip-32.txt", hosts + (hosts ? "\n" : ""), "text/plain;charset=utf-8"); }}><Icon name="download" />Riskli IP /32 listesi</button>
                  <button className="button button-secondary compact" type="button" onClick={() => download("mssoft-ip-sentinel-detay.json", JSON.stringify({ generatedAt: new Date().toISOString(), scanned, findings }, null, 2), "application/json")}><Icon name="download" />Detay JSON</button>
                </div>
              </div>
              <div className="result-stats">
                <div><span>Taranan IP</span><strong>{formatNumber(scanned)}</strong></div>
                <div><span>Eşik üstü kayıt</span><strong>{formatNumber(findings.length)}</strong></div>
                <div><span>Tarama durumu</span><strong>{running ? "Sürüyor" : cancelled ? "İptal" : "Tamamlandı"}</strong></div>
              </div>
              <div className="table-shell">
                <table>
                  <thead><tr><th>IP / Prefix</th><th>Skor</th><th>Rapor</th><th>ASN</th><th>Ülke</th><th>Prefix kaynağı</th></tr></thead>
                  <tbody>{findings.length ? findings.map((item) => <tr key={`${item.ip_with_prefix}-${item.abuse_confidence_score}`}><td>{item.ip_with_prefix}</td><td className="score-cell">{item.abuse_confidence_score}</td><td>{item.total_reports}</td><td>{item.origin_asns?.join(", ") || "—"}</td><td>{item.country || "—"}</td><td>{item.prefix_source || "—"}</td></tr>) : <tr><td colSpan="6" className="empty-cell">Seçilen eşik üzerinde kayıt bulunmadı.</td></tr>}</tbody>
                </table>
              </div>
            </section>
          </AnimatedContent>
        )}

        <AnimatedContent distance={16} duration={0.4}>
          <section className="data-note">
            <div><p className="section-label">VERİ YAKLAŞIMI</p><h2>Dosya cihazınızda kalır.</h2></div>
            <p>Ham dosya tarayıcıda okunur. Kurum geçidine yalnızca tekilleştirilmiş genel IPv4 adresleri, seçilen eşik ve rapor yaşı iletilir. Portal API anahtarı saklamaz.</p>
          </section>
        </AnimatedContent>
      </main>

      {settingsOpen && <div className="dialog-backdrop" role="presentation" onMouseDown={() => setSettingsOpen(false)}>
        <section className="dialog" role="dialog" aria-modal="true" aria-labelledby="settings-title" onMouseDown={(event) => event.stopPropagation()}>
          <div className="dialog-header"><div><p className="section-label">EKİP AYARLARI</p><h2 id="settings-title">Kurum geçidi</h2></div><button className="close-button" onClick={() => setSettingsOpen(false)} aria-label="Ayarları kapat">×</button></div>
          <p>Yalnız kurum yöneticinizin sağladığı HTTPS geçit adresini kullanın. Adres sadece aktif tarayıcı oturumunda saklanır.</p>
          <label className="gateway-label">Geçit adresi<input type="url" inputMode="url" value={gatewayDraft} onChange={(event) => setGatewayDraft(event.target.value)} placeholder="https://ornek.workers.dev" autoComplete="off" /></label>
          {gatewayError && <p className="form-error">{gatewayError}</p>}
          <div className="dialog-actions"><button className="button button-secondary" type="button" onClick={() => setSettingsOpen(false)}>Vazgeç</button><button className="button button-primary" type="button" onClick={saveGateway}>Kaydet <Icon name="chevron" /></button></div>
        </section>
      </div>}
    </div>
  );
}

export default App;
