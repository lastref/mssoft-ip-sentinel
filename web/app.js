const MAX_FILE_BYTES = 100 * 1024 * 1024;
const BATCH_SIZE = 50;
const ipPattern = /(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])/g;
const ui = Object.fromEntries(["fileInput","fileName","ipCount","duplicateCount","scoreInput","daysInput","scanButton","cancelButton","statusDot","statusTitle","statusMessage","progressLabel","progressBar","results","scannedCount","findingCount","cancelledCount","resultsBody","downloadSummary","downloadDetails","settingsDialog","showSettings","closeSettings","saveSettings","gatewayInput","gatewayStatus","serviceNotice"].map((id) => [id, document.getElementById(id)]));
let ips = [], findings = [], controller = null, cancelled = false;
const gatewayKey = "mssoft-ip-sentinel-gateway";

function isRoutable(ip) {
  const [a, b] = ip.split(".").map(Number);
  if (a === 0 || a === 10 || a === 127 || a >= 224 || a >= 240) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && (b === 0 || b === 168)) return false;
  if (a === 198 && (b === 18 || b === 19 || b === 51)) return false;
  if (a === 203 && b === 0) return false;
  return true;
}
function gateway() { return sessionStorage.getItem(gatewayKey) || ""; }
function setStatus(title, message, tone = "neutral") { ui.statusTitle.textContent = title; ui.statusMessage.textContent = message; ui.statusDot.className = `status-dot ${tone === "neutral" ? "" : tone}`; }
function setProgress(done, total) { const value = total ? Math.min(100, Math.round(done / total * 100)) : 0; ui.progressBar.style.width = `${value}%`; ui.progressLabel.textContent = `${done} / ${total}`; }
function updateStartState() { ui.scanButton.disabled = !ips.length || !gateway() || Boolean(controller); ui.serviceNotice.hidden = Boolean(gateway()); }
function download(filename, content, type) { const blob = new Blob([content], { type }); const url = URL.createObjectURL(blob); const link = document.createElement("a"); link.href = url; link.download = filename; link.click(); URL.revokeObjectURL(url); }

ui.fileInput.addEventListener("change", async () => {
  const [file] = ui.fileInput.files;
  if (!file) return;
  if (file.size > MAX_FILE_BYTES) { setStatus("Dosya çok büyük", "100 MB sınırını aşan dosyalar güvenli nedenlerle işlenmez.", "error"); return; }
  const text = await file.text();
  const matches = text.match(ipPattern) || [];
  const unique = [...new Set(matches.filter(isRoutable))].sort((x, y) => x.split(".").reduce((sum, part, index) => sum + Number(part) * 256 ** (3 - index), 0) - y.split(".").reduce((sum, part, index) => sum + Number(part) * 256 ** (3 - index), 0));
  ips = unique; findings = []; ui.fileName.textContent = file.name; ui.ipCount.textContent = unique.length.toLocaleString("tr-TR"); ui.duplicateCount.textContent = Math.max(0, matches.filter(isRoutable).length - unique.length).toLocaleString("tr-TR"); ui.results.hidden = true; setProgress(0, unique.length);
  setStatus(unique.length ? "Girdi hazır" : "Taranacak genel IP bulunamadı", unique.length ? `${unique.length.toLocaleString("tr-TR")} benzersiz genel IPv4 hazırlandı; ham log cihazınızda kaldı.` : "Dosyada yalnız özel, ayrılmış veya geçersiz adresler var.", unique.length ? "neutral" : "error"); updateStartState();
});

ui.showSettings.onclick = () => { ui.gatewayInput.value = gateway(); ui.gatewayStatus.textContent = ""; ui.settingsDialog.showModal(); };
ui.closeSettings.onclick = () => ui.settingsDialog.close();
ui.saveSettings.onclick = () => { try { const url = new URL(ui.gatewayInput.value.trim()); if (url.protocol !== "https:") throw new Error(); sessionStorage.setItem(gatewayKey, url.href.replace(/\/$/, "")); ui.settingsDialog.close(); setStatus("Geçit hazır", "Güvenli ekip geçidi bu tarayıcı oturumu için kaydedildi."); updateStartState(); } catch { ui.gatewayStatus.textContent = "Geçerli bir HTTPS Worker adresi girin."; ui.gatewayStatus.className = "gateway-status error"; } };
ui.cancelButton.onclick = () => { cancelled = true; controller?.abort(); ui.cancelButton.disabled = true; setStatus("İptal isteniyor", "Geçerli istek sonlandırılıyor; tamamlanan bulgular korunacak.", "active"); };

async function scan() {
  const score = Number(ui.scoreInput.value), days = Number(ui.daysInput.value);
  if (!Number.isInteger(score) || score < 0 || score > 100 || !Number.isInteger(days) || days < 1 || days > 365) { setStatus("Geçersiz politika", "Skor 0–100, rapor yaşı 1–365 arasında olmalıdır.", "error"); return; }
  controller = new AbortController(); cancelled = false; findings = []; ui.scanButton.disabled = true; ui.cancelButton.disabled = false; ui.results.hidden = true; setStatus("Tarama sürüyor", "IP’ler güvenli ekip geçidine küçük gruplar halinde gönderiliyor.", "active");
  let done = 0;
  try {
    for (let index = 0; index < ips.length; index += BATCH_SIZE) {
      if (cancelled) break;
      const response = await fetch(`${gateway()}/api/scan`, { method:"POST", signal:controller.signal, headers:{"Content-Type":"application/json"}, body:JSON.stringify({ ips:ips.slice(index,index + BATCH_SIZE), score, maxAgeInDays:days }) });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload.error || `Geçit HTTP ${response.status} yanıtı verdi.`);
      findings.push(...(payload.findings || [])); done += payload.scanned ?? Math.min(BATCH_SIZE, ips.length - index); setProgress(done, ips.length);
    }
    renderResults(done); setStatus(cancelled ? "Tarama iptal edildi" : "Tarama tamamlandı", `${done.toLocaleString("tr-TR")} IP işlendi, ${findings.length.toLocaleString("tr-TR")} eşik üstü bulgu bulundu.`, cancelled ? "neutral" : "success");
  } catch (error) { if (error.name !== "AbortError") setStatus("Tarama durdu", error.message || "Geçit erişilemedi. Ekip erişimi ve geçit adresini kontrol edin.", "error"); renderResults(done); }
  finally { controller = null; ui.cancelButton.disabled = true; updateStartState(); }
}
function renderResults(scanned) { ui.scannedCount.textContent = scanned.toLocaleString("tr-TR"); ui.findingCount.textContent = findings.length.toLocaleString("tr-TR"); ui.cancelledCount.textContent = cancelled ? "Evet" : "Hayır"; ui.resultsBody.replaceChildren(...findings.map((item) => { const row = document.createElement("tr"); [item.ip_with_prefix, item.abuse_confidence_score, item.total_reports, (item.origin_asns || []).join(", ") || "—", item.country || "—", item.prefix_source || "—"].forEach((value, index) => { const cell = document.createElement("td"); cell.textContent = value; if (index === 1) cell.className = "score"; row.append(cell); }); return row; })); if (!findings.length) ui.resultsBody.innerHTML = "<tr><td colspan=\"6\">Eşik üstü bulgu bulunmadı.</td></tr>"; ui.results.hidden = false; }
ui.downloadSummary.onclick = () => download("mssoft-ip-sentinel-ip-prefix.txt", findings.map((item) => item.ip_with_prefix).join("\n") + (findings.length ? "\n" : ""), "text/plain;charset=utf-8");
ui.downloadDetails.onclick = () => download("mssoft-ip-sentinel-details.json", JSON.stringify({ generatedAt:new Date().toISOString(), findings }, null, 2), "application/json");
ui.scanButton.onclick = scan; updateStartState();
