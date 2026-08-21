const API_URL = "https://api.abuseipdb.com/api/v2/check";
const RIPE_URL = "https://stat.ripe.net/data/network-info/data.json";
const DAILY_LIMIT = 1000;
// Free Worker planlarında bir çağrının alt istek sayısı sınırlıdır. Her IP için
// AbuseIPDB, anahtar havuzu ve gerektiğinde RIPEstat çağrıları yapıldığından,
// 8'lik grup güvenli bir üst sınır bırakır.
const MAX_BATCH = 8;
const MAX_KEY_ATTEMPTS = 2;
const IP_PATTERN = /^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

function cors(request, env) {
  const origin = request.headers.get("Origin");
  const allowed = env.ALLOWED_ORIGIN;
  if (!origin || origin !== allowed) return null;
  return { "Access-Control-Allow-Origin": origin, "Access-Control-Allow-Methods":"GET, POST, OPTIONS", "Access-Control-Allow-Headers":"Content-Type", "Vary":"Origin" };
}
function response(request, env, payload, status = 200) {
  const headers = cors(request, env);
  if (!headers) return new Response(JSON.stringify({ error:"Origin not allowed." }), { status:403, headers:{"Content-Type":"application/json"} });
  return new Response(JSON.stringify(payload), { status, headers:{...headers, "Content-Type":"application/json", "Cache-Control":"no-store"} });
}
function isRoutable(ip) { const [a,b] = ip.split(".").map(Number); return IP_PATTERN.test(ip) && !(a===0 || a===10 || a===127 || a>=224 || a>=240 || (a===100 && b>=64 && b<=127) || (a===169 && b===254) || (a===172 && b>=16 && b<=31) || (a===192 && (b===0 || b===168)) || (a===198 && (b===18 || b===19 || b===51)) || (a===203 && b===0)); }
function keyList(env) { const keys = (env.ABUSEIPDB_API_KEYS || "").split(",").map((value) => value.trim()).filter(Boolean); if (!keys.length) throw new Error("Gateway API anahtarları yapılandırılmadı."); return keys; }

export class ApiKeyPool {
  constructor(state, env) { this.state = state; this.env = env; }
  async fetch(request) {
    const keys = keyList(this.env); const today = new Date().toISOString().slice(0, 10); const data = await this.state.storage.get("usage") || { day:today, counts:{}, exhausted:{} };
    if (data.day !== today) { data.day = today; data.counts = {}; data.exhausted = {}; await this.state.storage.put("usage", data); }
    const url = new URL(request.url);
    if (url.pathname === "/usage") return Response.json({ day: data.day, keys: keys.map((_, index) => { const used = data.counts[index] || 0; return { label:`API ${index + 1}`, used, limit:DAILY_LIMIT, remaining:Math.max(0, DAILY_LIMIT - used), exhausted:Boolean(data.exhausted[index]) }; }) });
    if (url.pathname === "/exhaust") { const index = Number(url.searchParams.get("index")); if (Number.isInteger(index)) data.exhausted[index] = true; await this.state.storage.put("usage", data); return Response.json({ ok:true }); }
    for (let index = 0; index < keys.length; index += 1) { if (data.exhausted[index]) continue; const count = data.counts[index] || 0; if (count >= DAILY_LIMIT) continue; data.counts[index] = count + 1; await this.state.storage.put("usage", data); return Response.json({ index }); }
    return Response.json({ error:"Tüm ekip API anahtarı günlük kota sınırında." }, { status:429 });
  }
}
async function reserveKey(env) { const id = env.API_KEY_POOL.idFromName("team"); const result = await env.API_KEY_POOL.get(id).fetch("https://pool/reserve"); if (!result.ok) throw new Error((await result.json()).error); return (await result.json()).index; }
async function exhaustKey(env, index) { const id = env.API_KEY_POOL.idFromName("team"); await env.API_KEY_POOL.get(id).fetch(`https://pool/exhaust?index=${index}`); }
async function usageFor(env) { const id = env.API_KEY_POOL.idFromName("team"); const result = await env.API_KEY_POOL.get(id).fetch("https://pool/usage"); if (!result.ok) throw new Error((await result.json()).error || "Kullanım bilgisi alınamadı."); return result.json(); }
async function prefixFor(ip) { try { const response = await fetch(`${RIPE_URL}?resource=${encodeURIComponent(ip)}`); const body = await response.json(); const prefix = body?.data?.prefix; if (typeof prefix === "string" && prefix.includes("/")) return { prefix, source:"ripestat_bgp" }; } catch {} return { prefix:`${ip}/32`, source:"host_32_fallback" }; }
async function lookup(ip, maxAgeInDays, env) {
  const keys = keyList(env); let lastError = "AbuseIPDB sorgusu tamamlanamadı.";
  // Bir IP için en fazla iki anahtar denenir. En kötü durumda 8 IP ×
  // (anahtar havuzu + AbuseIPDB + devre dışı bırakma + ikinci deneme +
  // RIPEstat) 50 alt isteğin altında kalır.
  for (let attempt = 0; attempt < Math.min(keys.length, MAX_KEY_ATTEMPTS); attempt += 1) {
    const index = await reserveKey(env); const url = new URL(API_URL); url.searchParams.set("ipAddress", ip); url.searchParams.set("maxAgeInDays", String(maxAgeInDays)); url.searchParams.set("verbose", "");
    try { const response = await fetch(url, { headers:{"Accept":"application/json", "Key":keys[index]} }); if ([401,403,429].includes(response.status)) { await exhaustKey(env, index); lastError = `Anahtar ${response.status} ile devre dışı kaldı.`; continue; } if (!response.ok) throw new Error(`AbuseIPDB HTTP ${response.status}`); const data = (await response.json()).data; if (data?.ipAddress !== ip) throw new Error("AbuseIPDB yanıt IP’si istekle uyuşmuyor."); return data; } catch (error) { lastError = error.message; }
  } throw new Error(lastError);
}
export default { async fetch(request, env) {
  const headers = cors(request, env); if (request.method === "OPTIONS") return headers ? new Response(null, { status:204, headers }) : new Response(null, { status:403 });
  const path = new URL(request.url).pathname;
  if (request.method === "GET" && path === "/api/usage") { try { return response(request, env, await usageFor(env)); } catch (error) { return response(request, env, { error:error.message || "Kullanım bilgisi alınamadı." }, 502); } }
  if (request.method !== "POST" || path !== "/api/scan") return response(request, env, { error:"Not found." }, 404);
  try { const body = await request.json(); const source = Array.isArray(body.ips) ? body.ips : []; const ips = [...new Set(source)].filter(isRoutable); const score = Number(body.score), maxAgeInDays = Number(body.maxAgeInDays); if (source.length > MAX_BATCH || !Number.isInteger(score) || score < 0 || score > 100 || !Number.isInteger(maxAgeInDays) || maxAgeInDays < 1 || maxAgeInDays > 365) return response(request, env, { error:"Geçersiz tarama isteği." }, 400); const findings = [];
    for (const ip of ips) { const data = await lookup(ip, maxAgeInDays, env); if ((data.abuseConfidenceScore || 0) >= score) { const subnet = await prefixFor(ip); findings.push({ ip, ip_with_prefix:subnet.prefix, prefix_source:subnet.source, abuse_confidence_score:data.abuseConfidenceScore || 0, total_reports:data.totalReports || 0, distinct_reporters:data.numDistinctUsers || 0, last_reported_at:data.lastReportedAt || null, country:data.countryCode || null, isp:data.isp || null, domain:data.domain || null, usage_type:data.usageType || null, is_whitelisted:data.isWhitelisted ?? null, origin_asns:[] }); } }
    return response(request, env, { scanned:ips.length, findings });
  } catch (error) { return response(request, env, { error:error.message || "Gateway isteği işlenemedi." }, 502); }
} };
