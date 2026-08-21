from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
import logging
import os
import re
import tempfile
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterator, TextIO

import requests


ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
RIPESTAT_URL = "https://stat.ripe.net/data/network-info/data.json"
MAX_INPUT_SIZE_BYTES = 100 * 1024 * 1024
MAX_PASTED_INPUT_BYTES = 1 * 1024 * 1024
READ_CHUNK_SIZE = 1024 * 1024
MATCH_OVERLAP_SIZE = 64
CONNECT_TIMEOUT_SECONDS = 5
READ_TIMEOUT_SECONDS = 15
NETWORK_RETRY_DELAYS = (0.4, 1.0)
REQUEST_PACING_SECONDS = 0.05
REQUESTS_PER_KEY_LIMIT = 1_000
USAGE_DIRECTORY = Path.home() / ".mssoft-ip-sentinel"
USAGE_LEDGER_PATH = USAGE_DIRECTORY / "api_usage.json"
USAGE_LOCK_PATH = USAGE_DIRECTORY / "api_usage.lock"
IP_PATTERN = re.compile(
    r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])"
)
FORTI_SRCIP_PATTERN = re.compile(r'\bsrcip\s*=\s*"((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})"', re.IGNORECASE)
FORTI_SRCIP_FIELD_PATTERN = re.compile(r"\bsrcip\s*=", re.IGNORECASE)


@dataclass
class Finding:
    ip: str
    ip_with_prefix: str
    bgp_prefix: str | None
    prefix_source: str
    bgp_lookup_status: str
    origin_asns: list[int]
    abuse_confidence_score: int
    total_reports: int
    distinct_reporters: int
    last_reported_at: str | None
    country: str | None
    isp: str | None
    domain: str | None
    usage_type: str | None
    is_whitelisted: bool | None
    api_key_label: str


class UsageLedger:
    """Atomically reserve daily API attempts without storing an API secret."""

    def __init__(self) -> None:
        USAGE_DIRECTORY.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            USAGE_DIRECTORY.chmod(0o700)
        except OSError:
            pass

    @staticmethod
    def _fingerprint(secret: str) -> str:
        return hashlib.sha256(secret.encode("utf-8")).hexdigest()

    def _acquire_lock(self) -> int:
        deadline = time.monotonic() + 5
        while True:
            try:
                return os.open(USAGE_LOCK_PATH, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                try:
                    if time.time() - USAGE_LOCK_PATH.stat().st_mtime > 60:
                        USAGE_LOCK_PATH.unlink(missing_ok=True)
                        continue
                except OSError:
                    pass
                if time.monotonic() >= deadline:
                    raise RuntimeError("API kota sayacına güvenli erişim sağlanamadı.")
                time.sleep(0.02)

    @staticmethod
    def _read() -> dict[str, object]:
        if not USAGE_LEDGER_PATH.exists():
            return {"version": 1, "days": {}}
        try:
            payload = json.loads(USAGE_LEDGER_PATH.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            raise RuntimeError("API kota sayacı bozuk; güvenli olarak durduruldu.") from error
        if not isinstance(payload, dict) or not isinstance(payload.get("days"), dict):
            raise RuntimeError("API kota sayacı doğrulanamadı; güvenli olarak durduruldu.")
        return payload

    @staticmethod
    def _write(payload: dict[str, object]) -> None:
        descriptor, temporary_name = tempfile.mkstemp(prefix="usage-", suffix=".json", dir=USAGE_DIRECTORY, text=True)
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            temporary_path.chmod(0o600)
            temporary_path.replace(USAGE_LEDGER_PATH)
            try:
                directory_fd = os.open(USAGE_DIRECTORY, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except OSError:
                pass
        finally:
            if temporary_path.exists():
                temporary_path.unlink(missing_ok=True)

    def reserve(self, secret: str, limit: int = REQUESTS_PER_KEY_LIMIT) -> int | None:
        lock_descriptor = self._acquire_lock()
        try:
            payload = self._read()
            days = payload["days"]
            assert isinstance(days, dict)
            today = datetime.now(timezone.utc).date().isoformat()
            raw_counts = days.get(today, {})
            if not isinstance(raw_counts, dict):
                raise RuntimeError("API kota sayacı doğrulanamadı; güvenli olarak durduruldu.")
            fingerprint = self._fingerprint(secret)
            count = raw_counts.get(fingerprint, 0)
            if not isinstance(count, int) or isinstance(count, bool) or count < 0:
                raise RuntimeError("API kota sayacı doğrulanamadı; güvenli olarak durduruldu.")
            if count >= limit:
                return None
            # Keep all current-day keys so a rotation or a second local process
            # cannot reset another key's durable budget; discard old days only.
            days.clear()
            current_counts = dict(raw_counts)
            current_counts[fingerprint] = count + 1
            days[today] = current_counts
            payload["version"] = 1
            self._write(payload)
            return count + 1
        finally:
            os.close(lock_descriptor)
            try:
                USAGE_LOCK_PATH.unlink(missing_ok=True)
            except OSError:
                pass

    def usage_for(self, keys: list[tuple[str, str]], limit: int = REQUESTS_PER_KEY_LIMIT) -> list[dict[str, int | str]]:
        """Return daily per-label usage without exposing API key material."""
        lock_descriptor = self._acquire_lock()
        try:
            payload = self._read()
            days = payload["days"]
            assert isinstance(days, dict)
            today = datetime.now(timezone.utc).date().isoformat()
            raw_counts = days.get(today, {})
            if not isinstance(raw_counts, dict):
                raise RuntimeError("API kota sayacı doğrulanamadı; güvenli olarak durduruldu.")
            usage: list[dict[str, int | str]] = []
            for index, (label, secret) in enumerate(keys, 1):
                count = raw_counts.get(self._fingerprint(secret), 0)
                if not isinstance(count, int) or isinstance(count, bool) or count < 0:
                    raise RuntimeError("API kota sayacı doğrulanamadı; güvenli olarak durduruldu.")
                used = min(count, limit)
                usage.append({"label": label, "position": index, "used": used, "limit": limit, "remaining": max(0, limit - used)})
            return usage
        finally:
            os.close(lock_descriptor)
            try:
                USAGE_LOCK_PATH.unlink(missing_ok=True)
            except OSError:
                pass


def api_usage_for_keys(keys: list[tuple[str, str]]) -> list[dict[str, int | str]]:
    """Expose an application-safe usage snapshot for the desktop interface."""
    return UsageLedger().usage_for(keys)


class ApiKeyPool:
    def __init__(self, keys: list[tuple[str, str]], notify: Callable[[str], None]) -> None:
        self.keys = keys
        self.notify = notify
        self.index = 0
        self.exhausted: set[int] = set()
        self.ledger = UsageLedger()
        self.attempts = [0] * len(keys)

    def current(self) -> tuple[str, str] | None:
        for _ in range(len(self.keys)):
            if self.index not in self.exhausted:
                return self.keys[self.index]
            self.index = (self.index + 1) % len(self.keys)
        return None

    def rotate(self, reason: str, index: int | None = None) -> None:
        if not self.keys:
            return
        previous = self.index if index is None else index
        self.exhausted.add(previous)
        self.index = (previous + 1) % len(self.keys)
        next_key = self.current()
        if next_key:
            self.notify(f"{self.keys[previous][0]} devre dışı: {reason}. Sıradaki API anahtarına geçildi: {next_key[0]}.")
        else:
            self.notify("Kullanılabilir AbuseIPDB API anahtarı kalmadı.")

    def reserve_attempt(self, key_index: int) -> bool:
        """Reserve one request immediately before each AbuseIPDB HTTP attempt."""
        if key_index in self.exhausted:
            return False
        _, secret = self.keys[key_index]
        count = self.ledger.reserve(secret, REQUESTS_PER_KEY_LIMIT)
        if count is None:
            self.rotate(f"günlük {REQUESTS_PER_KEY_LIMIT} istek kotası", key_index)
            return False
        self.attempts[key_index] += 1
        return True


def _iter_matches(path: Path, pattern: re.Pattern[str]) -> Iterator[str]:
    """Yield regex captures without losing an IPv4 token at a chunk boundary."""
    carry = ""
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        while chunk := handle.read(READ_CHUNK_SIZE):
            text = carry + chunk
            safe_end = max(0, len(text) - MATCH_OVERLAP_SIZE)
            for match in pattern.finditer(text):
                # A token whose *start* is before the retained tail is complete
                # in this buffer and cannot be reconstructed next time: the tail
                # will no longer contain its beginning.  Emitting by end-offset
                # loses exactly those boundary-spanning IPv4 values.
                if match.start() < safe_end:
                    yield match.group(1) if match.lastindex else match.group(0)
            carry = text[-MATCH_OVERLAP_SIZE:]
    for match in pattern.finditer(carry):
        yield match.group(1) if match.lastindex else match.group(0)


def _is_acceptable_public_ipv4(value: str) -> bool:
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        return False
    return address.is_global and not any((
        address.is_private, address.is_loopback, address.is_link_local,
        address.is_multicast, address.is_unspecified, address.is_reserved,
    ))


def _unique_public_ipv4(path: Path, pattern: re.Pattern[str]) -> list[str]:
    unique = {value for value in _iter_matches(path, pattern) if _is_acceptable_public_ipv4(value)}
    return sorted(unique, key=lambda value: int(ipaddress.IPv4Address(value)))


def _contains_forti_srcip_field(path: Path) -> bool:
    return any(_iter_matches(path, FORTI_SRCIP_FIELD_PATTERN))


def extract_ips(path: Path) -> tuple[list[str], str]:
    if path.stat().st_size > MAX_INPUT_SIZE_BYTES:
        raise ValueError("Girdi dosyası en fazla 100 MB olabilir.")
    # Never fall back to destination/other fields once a Forti source field is present.
    if _contains_forti_srcip_field(path):
        return _unique_public_ipv4(path, FORTI_SRCIP_PATTERN), "FortiAnalyzer srcip"
    return _unique_public_ipv4(path, IP_PATTERN), "IPv4 listesi"


def extract_pasted_ips(text: str) -> tuple[list[str], str]:
    """Extract de-duplicated public IPv4 addresses pasted into the desktop UI."""
    if len(text.encode("utf-8")) > MAX_PASTED_INPUT_BYTES:
        raise ValueError("Yapıştırılan IP listesi en fazla 1 MB olabilir.")
    unique = {match.group(0) for match in IP_PATTERN.finditer(text) if _is_acceptable_public_ipv4(match.group(0))}
    return sorted(unique, key=lambda value: int(ipaddress.IPv4Address(value))), "Yapıştırılan IPv4 listesi"


def _request(session: requests.Session, url: str, **kwargs: object) -> requests.Response:
    return session.get(url, timeout=(CONNECT_TIMEOUT_SECONDS, READ_TIMEOUT_SECONDS), allow_redirects=False, **kwargs)


def _request_with_retries(
    session: requests.Session,
    url: str,
    cancel_event: threading.Event,
    before_attempt: Callable[[], bool] | None = None,
    **kwargs: object,
) -> requests.Response | None:
    """Retry transient failures and account for every API attempt before sending it."""
    for attempt in range(len(NETWORK_RETRY_DELAYS) + 1):
        if cancel_event.is_set() or (before_attempt is not None and not before_attempt()):
            return None
        try:
            response = _request(session, url, **kwargs)
        except requests.RequestException:
            response = None
        if response is not None and response.status_code not in {500, 502, 503, 504}:
            return response
        if response is not None:
            response.close()
        if attempt < len(NETWORK_RETRY_DELAYS) and cancel_event.wait(NETWORK_RETRY_DELAYS[attempt]):
            return None
    return None


def _bgp_prefix(session: requests.Session, ip: str, cancel_event: threading.Event) -> tuple[str | None, list[int], str]:
    response = _request_with_retries(session, RIPESTAT_URL, cancel_event, params={"resource": ip})
    if response is None:
        return None, [], "unavailable"
    if response.status_code != 200:
        status = f"http_{response.status_code}"
        response.close()
        return None, [], status
    try:
        payload = response.json().get("data", {})
    except (AttributeError, ValueError):
        return None, [], "invalid_response"
    finally:
        response.close()
    if not isinstance(payload, dict):
        return None, [], "invalid_response"
    prefix = payload.get("prefix")
    asns = [value for value in payload.get("asns", []) if isinstance(value, int) and not isinstance(value, bool)]
    if not isinstance(prefix, str):
        return None, asns, "no_prefix"
    try:
        network = ipaddress.ip_network(prefix, strict=False)
        address = ipaddress.IPv4Address(ip)
        if network.version != 4 or address not in network:
            return None, asns, "invalid_prefix"
    except ValueError:
        return None, asns, "invalid_prefix"
    return str(network), asns, "verified"


def _summary_prefix(ip: str, prefix: str | None) -> tuple[str, str]:
    if prefix:
        network = ipaddress.ip_network(prefix, strict=False)
        return f"{ip}/{network.prefixlen}", "ripe_bgp"
    return f"{ip}/32", "host_32_fallback"


def _run_dir(parent: Path) -> Path:
    parent = parent.resolve()
    if not parent.is_dir():
        raise ValueError("Çıktı üst klasörü geçerli bir klasör değil.")
    stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    for suffix in range(1000):
        name = f"MSSOFT_IP_Sentinel_{stamp}" if suffix == 0 else f"MSSOFT_IP_Sentinel_{stamp}_{suffix:03d}"
        folder = parent / name
        try:
            folder.mkdir(mode=0o700)
            return folder
        except FileExistsError:
            continue
    raise RuntimeError("Yeni çıktı klasörü oluşturulamadı.")


def _safe_error(error: BaseException) -> str:
    message = str(error).replace("\n", " ").replace("\r", " ")
    return re.sub(r"(?i)(key|api[_ -]?key|token|authorization)=?[^\s,;]+", r"\1=[gizlendi]", message)[:300]


def _csv_safe(value: object) -> object:
    if value is None:
        return ""
    text = str(value).replace("\x00", "").replace("\r", " ").replace("\n", " ")
    text = "".join(char for char in text if ord(char) >= 32).strip()
    if text[:1] in {"=", "+", "-", "@"}:
        return "'" + text
    return text


def _int_or_default(value: object, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


class _ReportWriter:
    def __init__(self, run_dir: Path) -> None:
        self.run_dir = run_dir
        self._json_path = run_dir / ".detayli_rapor.json.partial"
        self._csv_path = run_dir / ".detayli_rapor.csv.partial"
        self._summary_path = run_dir / ".ozet_ipv4.txt.partial"
        self._json: TextIO = self._json_path.open("w", encoding="utf-8")
        self._csv_handle: TextIO = self._csv_path.open("w", newline="", encoding="utf-8")
        self._summary: TextIO = self._summary_path.open("w", encoding="utf-8")
        self._fields = list(Finding.__dataclass_fields__)
        self._csv = csv.DictWriter(self._csv_handle, fieldnames=self._fields)
        self._csv.writeheader()
        self._json.write("[\n")
        self._first = True
        self.count = 0

    def write(self, finding: Finding) -> None:
        payload = asdict(finding)
        if not self._first:
            self._json.write(",\n")
        json.dump(payload, self._json, ensure_ascii=False)
        self._first = False
        row = {field: _csv_safe(value) for field, value in payload.items()}
        row["origin_asns"] = ",".join(map(str, finding.origin_asns))
        self._csv.writerow(row)
        self._summary.write(f"{finding.ip_with_prefix}\n")
        self.count += 1

    def close(self) -> None:
        self._json.write("\n]\n")
        for handle in (self._json, self._csv_handle, self._summary):
            handle.flush()
            try:
                os.fsync(handle.fileno())
            except OSError:
                pass
            handle.close()
        self._json_path.replace(self.run_dir / "detayli_rapor.json")
        self._csv_path.replace(self.run_dir / "detayli_rapor.csv")
        self._summary_path.replace(self.run_dir / "ozet_ipv4.txt")


def _run_scan(ips: list[str], mode: str, input_reference: str, output_parent: Path, keys: list[tuple[str, str]], minimum_score: int, max_age_days: int, cancel_event: threading.Event, notify: Callable[[str], None], progress: Callable[[int, int], None]) -> Path:
    if not keys:
        raise ValueError("Ayarlar bölümüne en az bir AbuseIPDB API anahtarı ekleyin.")
    if not 0 <= minimum_score <= 100 or max_age_days < 1:
        raise ValueError("Skor 0-100 arasında, rapor yaşı en az 1 gün olmalı.")
    if not ips:
        raise ValueError("Girdide taranabilir genel IPv4 adresi bulunamadı.")

    run_dir = _run_dir(output_parent)
    logger = logging.getLogger(f"mssoft-ip-sentinel-{run_dir.name}")
    logger.handlers.clear()
    logger.setLevel(logging.INFO)
    logger.propagate = False
    handler = logging.FileHandler(run_dir / "audit.log", encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
    logger.addHandler(handler)
    failures = completed = 0
    pool = ApiKeyPool(keys, notify)
    session = requests.Session()
    session.trust_env = False
    reports = _ReportWriter(run_dir)
    notify(f"{len(ips)} benzersiz taranabilir IPv4 bulundu. Kaynak: {mode}.")

    try:
        for index, ip in enumerate(ips, 1):
            if cancel_event.is_set():
                notify("Tarama kullanıcı tarafından iptal edildi. Kısmi raporlar kaydediliyor.")
                break
            response: requests.Response | None = None
            label = ""
            while not cancel_event.is_set():
                active = pool.current()
                if not active:
                    break
                key_index = pool.index
                label, api_key = active
                notify(f"[{index}/{len(ips)}] {ip} sorgulanıyor ({label}).")
                response = _request_with_retries(session, ABUSEIPDB_URL, cancel_event, before_attempt=lambda key_index=key_index: pool.reserve_attempt(key_index), headers={"Accept": "application/json", "Key": api_key}, params={"ipAddress": ip, "maxAgeInDays": str(max_age_days), "verbose": "true"})
                if response is None:
                    if key_index in pool.exhausted:
                        continue
                    if not cancel_event.is_set():
                        failures += 1
                        logger.warning("%s için ağ/servis hatası, denemeler tükendi.", ip)
                    break
                if response.status_code in {401, 403, 429}:
                    response.close()
                    pool.rotate(f"HTTP {response.status_code}", key_index)
                    response = None
                    continue
                break

            if cancel_event.is_set():
                break
            if response is None:
                if not pool.current():
                    notify("API anahtarlarının tümü kota/yetki nedeniyle kullanılamaz durumda.")
                    break
                progress(index, len(ips))
                continue
            if response.status_code != 200:
                failures += 1
                logger.warning("%s HTTP %s", ip, response.status_code)
                response.close()
                progress(index, len(ips))
                continue
            try:
                payload = response.json()
                data = payload.get("data", {}) if isinstance(payload, dict) else {}
                returned_ip = data.get("ipAddress") if isinstance(data, dict) else None
                if not isinstance(data, dict) or returned_ip != ip:
                    raise ValueError("API IP doğrulaması başarısız")
                score = int(data.get("abuseConfidenceScore", 0))
            except (AttributeError, ValueError, TypeError):
                failures += 1
                logger.warning("%s için geçersiz veya doğrulanmamış API yanıtı alındı.", ip)
                response.close()
                progress(index, len(ips))
                continue
            response.close()
            completed += 1
            if score >= minimum_score:
                prefix, asns, bgp_status = _bgp_prefix(session, ip, cancel_event)
                ip_with_prefix, prefix_source = _summary_prefix(ip, prefix)
                finding = Finding(ip=ip, ip_with_prefix=ip_with_prefix, bgp_prefix=prefix, prefix_source=prefix_source, bgp_lookup_status=bgp_status, origin_asns=asns, abuse_confidence_score=score, total_reports=_int_or_default(data.get("totalReports")), distinct_reporters=_int_or_default(data.get("numDistinctUsers")), last_reported_at=data.get("lastReportedAt") if isinstance(data.get("lastReportedAt"), str) else None, country=data.get("countryCode") if isinstance(data.get("countryCode"), str) else None, isp=data.get("isp") if isinstance(data.get("isp"), str) else None, domain=data.get("domain") if isinstance(data.get("domain"), str) else None, usage_type=data.get("usageType") if isinstance(data.get("usageType"), str) else None, is_whitelisted=data.get("isWhitelisted") if isinstance(data.get("isWhitelisted"), bool) else None, api_key_label=label)
                reports.write(finding)
                prefix_note = "" if prefix_source == "ripe_bgp" else " | RIPEstat yok: güvenli /32"
                notify(f"Riskli: {finding.ip_with_prefix} | skor={score} | rapor={finding.total_reports}{prefix_note}")
            progress(index, len(ips))
            cancel_event.wait(REQUEST_PACING_SECONDS)
    finally:
        reports.close()
        session.close()
        logger.removeHandler(handler)
        handler.close()
    metadata = {"product": "MSSOFT IP Sentinel", "input": input_reference, "created_at": datetime.now(timezone.utc).isoformat(), "extraction_mode": mode, "unique_ipv4": len(ips), "completed_requests": completed, "api_request_attempts": sum(pool.attempts), "api_request_attempts_by_key": {keys[i][0]: pool.attempts[i] for i in range(len(keys))}, "risk_findings": reports.count, "failed_requests": failures, "cancelled": cancel_event.is_set(), "minimum_score": minimum_score, "max_age_days": max_age_days}
    (run_dir / "run.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    notify(f"Raporlar hazır: {run_dir}")
    return run_dir


def run_scan(input_path: Path, output_parent: Path, keys: list[tuple[str, str]], minimum_score: int, max_age_days: int, cancel_event: threading.Event, notify: Callable[[str], None], progress: Callable[[int, int], None]) -> Path:
    if not input_path.is_file():
        raise ValueError("Girdi dosyası bulunamadı.")
    ips, mode = extract_ips(input_path)
    return _run_scan(ips, mode, str(input_path), output_parent, keys, minimum_score, max_age_days, cancel_event, notify, progress)


def run_scan_from_ips(ips: list[str], output_parent: Path, keys: list[tuple[str, str]], minimum_score: int, max_age_days: int, cancel_event: threading.Event, notify: Callable[[str], None], progress: Callable[[int, int], None]) -> Path:
    unique = sorted({value for value in ips if _is_acceptable_public_ipv4(value)}, key=lambda value: int(ipaddress.IPv4Address(value)))
    return _run_scan(unique, "Yapıştırılan IPv4 listesi", "Yapıştırılan IP listesi", output_parent, keys, minimum_score, max_age_days, cancel_event, notify, progress)
