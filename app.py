from __future__ import annotations

import os
import queue
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk
from PIL import Image

from scanner import api_usage_for_keys, extract_pasted_ips, run_scan, run_scan_from_ips
from settings import SettingsStore


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")
MAX_CONSOLE_LINES = 1_000
CONSOLE_TRIM_LINES = 200
MAX_EVENT_QUEUE = 300
ACCENT = "#22C7D8"
SUCCESS = "#48C78E"
WARNING = "#F3B64A"
DANGER = "#F56B7A"
MUTED = "#AAB8D0"


class SentinelApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.title("MSSOFT IP Sentinel")
        self.geometry("1180x760")
        self.minsize(1000, 660)
        self.store = SettingsStore()
        self.cancel_event = threading.Event()
        self.events: queue.Queue[tuple[str, object]] = queue.Queue(maxsize=MAX_EVENT_QUEUE)
        self._dropped_log_events = 0
        self._console_lines = 0
        self._is_scanning = False
        self._scan_started_at: float | None = None
        self._latest_report: Path | None = None
        self.input_file = ctk.StringVar()
        self.output_folder = ctk.StringVar(value=str(Path.cwd()))
        self.score = ctk.StringVar(value="25")
        self.days = ctk.StringVar(value="90")
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._build()
        self._refresh_keys()
        self._set_status("Hazır", "Bir .txt/.log dosyası seçin veya IPv4 listesini doğrudan yapıştırın.", "neutral")
        self.after(100, self._consume_events)
        self.after(1_000, self._update_elapsed)
        self.after_idle(self.input_button.focus_set)
        for binding in ("<Control-o>", "<Command-o>"):
            self.bind_all(binding, lambda _event: self._select_input())
        for binding in ("<Control-Shift-O>", "<Command-Shift-O>"):
            self.bind_all(binding, lambda _event: self._select_output())
        for binding in ("<Control-Return>", "<Command-Return>"):
            self.bind_all(binding, lambda _event: self._start())
        self.bind_all("<Escape>", lambda _event: self._cancel())

    def _build(self) -> None:
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        sidebar = ctk.CTkFrame(self, width=250, corner_radius=0)
        sidebar.grid(row=0, column=0, sticky="nsew")
        main = ctk.CTkFrame(self, fg_color="transparent")
        main.grid(row=0, column=1, sticky="nsew", padx=24, pady=24)
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(4, weight=1)

        logo_path = Path(__file__).with_name("assets") / "mssoft_ip_sentinel_logo_minimal.png"
        try:
            self.logo = ctk.CTkImage(Image.open(logo_path), size=(112, 112))
            ctk.CTkLabel(sidebar, image=self.logo, text="").pack(pady=(36, 10))
        except (OSError, ValueError):
            self.logo = None
            ctk.CTkLabel(sidebar, text="M", text_color=ACCENT, font=ctk.CTkFont(size=72, weight="bold")).pack(pady=(36, 10))
        ctk.CTkLabel(sidebar, text="MSSOFT", font=ctk.CTkFont(size=25, weight="bold")).pack()
        ctk.CTkLabel(sidebar, text="IP Sentinel\nRisk Değerlendirme", text_color="#96a8c8").pack(pady=(2, 34))
        ctk.CTkLabel(sidebar, text="AbuseIPDB reputation\nRIPEstat BGP subnet\nWindows • macOS • Linux", justify="left", text_color="#7f91af").pack(padx=24, anchor="w")
        ctk.CTkLabel(sidebar, text="v1.0", text_color="#5b6b86").pack(side="bottom", pady=24)

        ctk.CTkLabel(main, text="IP Risk Değerlendirme", font=ctk.CTkFont(size=28, weight="bold")).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(main, text="IP listesi veya log taraması, çoklu API anahtarı kullanımı ve denetlenebilir çıktı yönetimi.", text_color="#8fa0bb").grid(row=1, column=0, sticky="w", pady=(2, 18))
        self.tabs = ctk.CTkTabview(main)
        self.tabs.grid(row=2, column=0, sticky="nsew")
        dashboard = self.tabs.add("Tarama")
        settings = self.tabs.add("Ayarlar")
        self._build_dashboard(dashboard)
        self._build_settings(settings)

    def _build_dashboard(self, frame: ctk.CTkFrame) -> None:
        frame.grid_columnconfigure(1, weight=1)
        frame.grid_rowconfigure(8, weight=1)
        ctk.CTkLabel(frame, text="Girdi dosyası", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, sticky="w", padx=18, pady=(20, 7))
        self.input_entry = ctk.CTkEntry(frame, textvariable=self.input_file, state="readonly")
        self.input_entry.grid(row=0, column=1, sticky="ew", padx=12, pady=(20, 7))
        self.input_button = ctk.CTkButton(frame, text="Dosya Seç", width=116, command=self._select_input)
        self.input_button.grid(row=0, column=2, padx=(0, 18), pady=(20, 7))
        ctk.CTkLabel(frame, text="veya IP listesini yapıştır", font=ctk.CTkFont(weight="bold")).grid(row=1, column=0, sticky="nw", padx=18, pady=(7, 7))
        self.paste_input = ctk.CTkTextbox(frame, height=80, font=ctk.CTkFont(family="Menlo", size=12), wrap="word")
        self.paste_input.grid(row=1, column=1, sticky="ew", padx=12, pady=7)
        self.paste_button = ctk.CTkButton(frame, text="Listeyi Hazırla", width=116, command=self._prepare_pasted_ips)
        self.paste_button.grid(row=1, column=2, padx=(0, 18), pady=7)
        ctk.CTkLabel(frame, text="Çıktı üst klasörü", font=ctk.CTkFont(weight="bold")).grid(row=2, column=0, sticky="w", padx=18, pady=7)
        self.output_entry = ctk.CTkEntry(frame, textvariable=self.output_folder, state="readonly")
        self.output_entry.grid(row=2, column=1, sticky="ew", padx=12, pady=7)
        self.output_button = ctk.CTkButton(frame, text="Klasör Seç", width=116, command=self._select_output)
        self.output_button.grid(row=2, column=2, padx=(0, 18), pady=7)
        controls = ctk.CTkFrame(frame, fg_color="#17243A")
        controls.grid(row=3, column=0, columnspan=3, sticky="ew", padx=18, pady=(12, 10))
        ctk.CTkLabel(controls, text="Minimum skor").pack(side="left")
        self.score_entry = ctk.CTkEntry(controls, textvariable=self.score, width=65, justify="center")
        self.score_entry.pack(side="left", padx=(8, 24))
        ctk.CTkLabel(controls, text="Rapor yaşı (gün)").pack(side="left")
        self.days_entry = ctk.CTkEntry(controls, textvariable=self.days, width=65, justify="center")
        self.days_entry.pack(side="left", padx=(8, 10))
        ctk.CTkLabel(controls, text="0–100 / 1–365", text_color="#8093B3", font=ctk.CTkFont(size=11)).pack(side="left")
        self.start = ctk.CTkButton(controls, text="Taramayı Başlat", fg_color="#1C8594", hover_color="#259DAC", command=self._start)
        self.start.pack(side="right")
        self.cancel = ctk.CTkButton(controls, text="İptal İsteği", fg_color="#78333D", hover_color="#9A414D", state="disabled", command=self._cancel)
        self.cancel.pack(side="right", padx=10)
        self.progress = ctk.CTkProgressBar(frame, progress_color=ACCENT)
        self.progress.set(0)
        self.progress.grid(row=4, column=0, columnspan=3, sticky="ew", padx=18, pady=(4, 2))
        self.progress_text = ctk.CTkLabel(frame, text="0 / 0 IP", anchor="e", text_color=MUTED, font=ctk.CTkFont(size=12))
        self.progress_text.grid(row=5, column=0, columnspan=3, sticky="ew", padx=18)
        status_card = ctk.CTkFrame(frame, fg_color="#152338", corner_radius=9)
        status_card.grid(row=6, column=0, columnspan=3, sticky="ew", padx=18, pady=(9, 8))
        self.status_indicator = ctk.CTkLabel(status_card, text="●", text_color=MUTED, width=24, font=ctk.CTkFont(size=18))
        self.status_indicator.grid(row=0, column=0, rowspan=2, padx=(12, 3), pady=9)
        self.status_title = ctk.CTkLabel(status_card, text="", anchor="w", font=ctk.CTkFont(weight="bold"))
        self.status_title.grid(row=0, column=1, sticky="ew", pady=(8, 0))
        self.status_detail = ctk.CTkLabel(status_card, text="", anchor="w", text_color=MUTED, wraplength=680, justify="left")
        self.status_detail.grid(row=1, column=1, sticky="ew", pady=(0, 8))
        status_card.grid_columnconfigure(1, weight=1)
        self.elapsed = ctk.CTkLabel(status_card, text="", text_color="#8FA0BB", font=ctk.CTkFont(size=12))
        self.elapsed.grid(row=0, column=2, rowspan=2, padx=12)
        console_header = ctk.CTkFrame(frame, fg_color="transparent")
        console_header.grid(row=7, column=0, columnspan=3, sticky="new", padx=18, pady=(0, 4))
        ctk.CTkLabel(console_header, text="İşlem günlüğü", font=ctk.CTkFont(weight="bold")).pack(side="left")
        self.open_results = ctk.CTkButton(console_header, text="Sonuç Klasörünü Aç", width=150, state="disabled", command=self._open_results)
        self.open_results.pack(side="right")
        self.console = ctk.CTkTextbox(frame, height=225, font=ctk.CTkFont(family="Menlo", size=12), wrap="word")
        self.console.grid(row=8, column=0, columnspan=3, sticky="nsew", padx=18, pady=(0, 20))
        self.console.configure(state="disabled")

    def _build_settings(self, frame: ctk.CTkFrame) -> None:
        ctk.CTkLabel(frame, text="AbuseIPDB API Anahtarları", font=ctk.CTkFont(size=20, weight="bold")).pack(anchor="w", padx=20, pady=(20, 4))
        ctk.CTkLabel(frame, text="Anahtar değerleri işletim sistemi güvenli anahtar kasasında saklanır. Yalnızca etiketler görünür; 1.000 başarılı sorguda sıradaki anahtar otomatik devralır.", text_color=MUTED, wraplength=780, justify="left").pack(anchor="w", padx=20)
        form = ctk.CTkFrame(frame, fg_color="#17243A")
        form.pack(fill="x", padx=20, pady=18)
        self.key_label = ctk.CTkEntry(form, placeholder_text="Etiket: SOC-01")
        self.key_label.grid(row=0, column=0, padx=12, pady=12, sticky="ew")
        self.key_value = ctk.CTkEntry(form, placeholder_text="AbuseIPDB API anahtarı", show="*")
        self.key_value.grid(row=0, column=1, padx=12, pady=12, sticky="ew")
        form.grid_columnconfigure(1, weight=1)
        self.key_add_button = ctk.CTkButton(form, text="Anahtar Ekle", command=self._add_key)
        self.key_add_button.grid(row=0, column=2, padx=12, pady=12)
        self.key_label.bind("<Return>", lambda _event: self.key_value.focus_set())
        self.key_value.bind("<Return>", lambda _event: self._add_key())
        self.keys_summary = ctk.CTkLabel(frame, text="", text_color=MUTED, font=ctk.CTkFont(size=12))
        self.keys_summary.pack(anchor="w", padx=20, pady=(0, 7))
        self.key_list = ctk.CTkScrollableFrame(frame, height=250, fg_color="#122035")
        self.key_list.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        self._settings_controls = (self.key_label, self.key_value, self.key_add_button)
        self._key_action_buttons: list[ctk.CTkButton] = []

    def _select_input(self) -> None:
        if self._is_scanning:
            return
        selected = filedialog.askopenfilename(title="Log veya IP listesi seçin", filetypes=[("Desteklenen dosyalar", "*.log *.txt"), ("Tüm dosyalar", "*.*")])
        if selected:
            self.paste_input.delete("1.0", "end")
            self.input_file.set(selected)
            self._write(f"Girdi seçildi: {Path(selected).name}")
            self._set_status("Girdi hazır", f"{Path(selected).name} seçildi. IP adresleri taramadan önce tekilleştirilecektir.", "neutral")

    def _prepare_pasted_ips(self) -> None:
        if self._is_scanning:
            return
        try:
            ips, _ = extract_pasted_ips(self.paste_input.get("1.0", "end-1c"))
        except ValueError as error:
            messagebox.showerror("IP listesi", self._safe_error(error), parent=self)
            return
        if not ips:
            messagebox.showerror("IP listesi", "Yapıştırılan metinde taranabilir genel IPv4 adresi bulunamadı.", parent=self)
            return
        self.input_file.set("")
        self._set_status("IP listesi hazır", f"{len(ips):,} benzersiz genel IPv4 bulundu. Tarama için Taramayı Başlat düğmesini kullanın.", "neutral")
        self._write(f"Yapıştırılan IP listesi hazırlandı: {len(ips):,} benzersiz genel IPv4")

    def _select_output(self) -> None:
        if self._is_scanning:
            return
        selected = filedialog.askdirectory(title="Çıktı üst klasörünü seçin")
        if selected:
            self.output_folder.set(selected)
            self._set_status("Çıktı klasörü güncellendi", Path(selected).name or selected, "neutral")

    def _refresh_keys(self) -> None:
        for child in self.key_list.winfo_children():
            child.destroy()
        self._key_action_buttons = []
        entries = self.store.list_keys()
        resolved_keys = self.store.resolved_keys()
        available = len(resolved_keys)
        try:
            usage_by_label = {str(item["label"]): item for item in api_usage_for_keys(resolved_keys)}
            usage_note = "  |  Sayaç: UTC günü"
        except Exception as error:
            usage_by_label = {}
            usage_note = "  |  Sayaç okunamadı: " + self._safe_error(error)
        _, secure, backend_message = self.store.keyring_status()
        warning = "" if secure else "  |  Uyarı: " + backend_message
        self.keys_summary.configure(text=f"Yapılandırılan: {len(entries)}  |  Kullanıma hazır: {available}{usage_note}{warning}")
        if not entries:
            ctk.CTkLabel(self.key_list, text="Henüz API anahtarı eklenmedi. Taramaya başlamadan önce en az bir anahtar ekleyin.", text_color=MUTED).pack(pady=20)
        for position, entry in enumerate(entries, 1):
            row = ctk.CTkFrame(self.key_list, fg_color="#192943")
            row.pack(fill="x", pady=5, padx=4)
            ctk.CTkLabel(row, text=f"API {position} · {entry['label']}", font=ctk.CTkFont(weight="bold")).pack(side="left", padx=12, pady=10)
            usage = usage_by_label.get(entry["label"])
            if usage:
                usage_text = f"Günlük kullanım: {usage['used']}/{usage['limit']}  |  Kalan: {usage['remaining']}"
            else:
                usage_text = "Kullanıma hazır değil veya sayaç okunamadı"
            ctk.CTkLabel(row, text=usage_text, text_color=MUTED, font=ctk.CTkFont(size=12)).pack(side="left")
            remove_button = ctk.CTkButton(row, text="Kaldır", width=80, fg_color="#78333D", hover_color="#9A414D", command=lambda item=entry: self._delete_key(item))
            remove_button.pack(side="right", padx=8, pady=6)
            self._key_action_buttons.append(remove_button)
        self._set_settings_controls(scanning=self._is_scanning)

    def _add_key(self) -> None:
        if self._is_scanning:
            return
        label, key = self.key_label.get().strip(), self.key_value.get().strip()
        if not label or not key:
            messagebox.showerror("Ayarlar", "Etiket ve API anahtarı zorunludur.", parent=self)
            return
        try:
            self.store.add_key(label, key)
        except Exception as error:
            messagebox.showerror("Anahtar kaydedilemedi", self._safe_error(error), parent=self)
            return
        self.key_label.delete(0, "end")
        self.key_value.delete(0, "end")
        self._refresh_keys()
        self._set_status("API anahtarı eklendi", f"{label} güvenli anahtar kasasına kaydedildi.", "success")
        self.key_label.focus_set()

    def _delete_key(self, entry: dict[str, str]) -> None:
        if self._is_scanning:
            return
        if messagebox.askyesno("Anahtarı kaldır", f"{entry['label']} anahtarını kaldırmak istiyor musunuz?", parent=self):
            try:
                self.store.delete_key(entry["id"])
            except Exception as error:
                messagebox.showerror("Anahtar kaldırılamadı", self._safe_error(error), parent=self)
                return
            self._refresh_keys()
            self._set_status("API anahtarı kaldırıldı", f"{entry['label']} artık kullanılmayacak.", "warning")

    def _validated_scan_inputs(self) -> tuple[Path | None, list[str] | None, str, Path, int, int] | None:
        output_path = Path(self.output_folder.get())
        pasted_text = self.paste_input.get("1.0", "end-1c")
        input_path: Path | None = None
        pasted_ips: list[str] | None = None
        source_name = ""
        if pasted_text.strip():
            try:
                pasted_ips, source_name = extract_pasted_ips(pasted_text)
            except ValueError as error:
                messagebox.showerror("Tarama", self._safe_error(error), parent=self)
                return None
            if not pasted_ips:
                messagebox.showerror("Tarama", "Yapıştırılan metinde taranabilir genel IPv4 adresi bulunamadı.", parent=self)
                self.paste_input.focus_set()
                return None
        else:
            input_path = Path(self.input_file.get())
            if not input_path.is_file():
                messagebox.showerror("Tarama", "Lütfen geçerli bir .txt/.log dosyası seçin veya IP listesini yapıştırın.", parent=self)
                self.input_button.focus_set()
                return None
            if input_path.suffix.lower() not in {".txt", ".log"}:
                if not messagebox.askyesno("Dosya türü", "Seçilen dosya .txt veya .log değil. Yine de metin olarak taransın mı?", parent=self):
                    return None
            source_name = input_path.name
        if not self._is_writable_output_folder(output_path):
            messagebox.showerror("Tarama", "Yazılabilir ve erişilebilir bir çıktı üst klasörü seçin.", parent=self)
            self.output_button.focus_set()
            return None
        try:
            score, days = int(self.score.get()), int(self.days.get())
        except ValueError:
            messagebox.showerror("Tarama", "Minimum skor ve rapor yaşı tam sayı olmalıdır.", parent=self)
            return None
        if not 0 <= score <= 100:
            messagebox.showerror("Tarama", "Minimum skor 0 ile 100 arasında olmalıdır.", parent=self)
            self.score_entry.focus_set()
            return None
        if not 1 <= days <= 365:
            messagebox.showerror("Tarama", "Rapor yaşı 1 ile 365 gün arasında olmalıdır.", parent=self)
            self.days_entry.focus_set()
            return None
        return input_path, pasted_ips, source_name, output_path, score, days

    @staticmethod
    def _is_writable_output_folder(path: Path) -> bool:
        try:
            resolved = path.resolve(strict=True)
            if not resolved.is_dir():
                return False
            descriptor, temporary_name = tempfile.mkstemp(prefix=".mssoft-write-test-", dir=resolved)
            os.close(descriptor)
            Path(temporary_name).unlink(missing_ok=True)
            return True
        except OSError:
            return False

    def _start(self) -> None:
        if self._is_scanning:
            return
        selected = self._validated_scan_inputs()
        if not selected:
            return
        input_path, pasted_ips, source_name, output_path, score, days = selected
        keys = self.store.resolved_keys()
        if not keys:
            self.tabs.set("Ayarlar")
            messagebox.showerror("Ayarlar", "Ayarlar sekmesine en az bir kullanılabilir API anahtarı ekleyin.", parent=self)
            self.key_label.focus_set()
            return
        self.cancel_event.clear()
        self.progress.set(0)
        self.progress_text.configure(text="Hazırlanıyor…")
        self._is_scanning = True
        self._scan_started_at = time.monotonic()
        self._set_scan_controls(scanning=True)
        self._set_settings_controls(scanning=True)
        self._set_status("Tarama başlatıldı", f"{source_name} işleniyor. İptal isterseniz kısmi raporlar güvenle kaydedilir.", "active")
        self._write(f"Tarama başlatıldı: {source_name} | eşik: {score} | rapor yaşı: {days} gün")
        self._write("API anahtarı ayarları bu tarama boyunca kilitlidir; değişiklikler sonraki taramada uygulanır.")
        threading.Thread(target=self._scan_thread, args=(input_path, pasted_ips, output_path, keys, score, days), daemon=True, name="ip-sentinel-scan").start()

    def _scan_thread(self, input_path: Path | None, pasted_ips: list[str] | None, output_path: Path, keys: list[tuple[str, str]], score: int, days: int) -> None:
        try:
            if pasted_ips is not None:
                result = run_scan_from_ips(pasted_ips, output_path, keys, score, days, self.cancel_event, self._enqueue_log, self._enqueue_progress)
            else:
                if input_path is None:
                    raise RuntimeError("Tarama girdisi bulunamadı.")
                result = run_scan(input_path, output_path, keys, score, days, self.cancel_event, self._enqueue_log, self._enqueue_progress)
            self._enqueue_critical("done", (str(result), self.cancel_event.is_set()))
        except Exception as error:
            self._enqueue_critical("error", self._safe_error(error))

    def _enqueue_log(self, text: str) -> None:
        try:
            self.events.put_nowait(("log", text))
        except queue.Full:
            self._dropped_log_events += 1

    def _enqueue_progress(self, current: int, total: int) -> None:
        try:
            self.events.put_nowait(("progress", (current, total)))
        except queue.Full:
            pass

    def _enqueue_critical(self, kind: str, value: object) -> None:
        # Completion and failure events must not be dropped; the UI drains the
        # bounded queue every 100 ms while this background worker waits briefly.
        self.events.put((kind, value))

    def _cancel(self) -> None:
        if not self._is_scanning or self.cancel_event.is_set():
            return
        self.cancel_event.set()
        self.cancel.configure(state="disabled", text="İptal bekleniyor")
        self._set_status("İptal isteği alındı", "Devam eden ağ isteği tamamlanacak; ardından kısmi raporlar kaydedilecektir.", "warning")
        self._write("İptal isteği alındı. Aktif sorgu tamamlandıktan sonra işlem duracak.")

    def _consume_events(self) -> None:
        try:
            if self._dropped_log_events:
                dropped = self._dropped_log_events
                self._dropped_log_events = 0
                self._write(f"[{dropped} ayrıntı günlüğü görüntü sınırı nedeniyle atlandı; tüm çalışma bilgisi audit.log içindedir.]")
            while True:
                kind, value = self.events.get_nowait()
                if kind == "log":
                    self._set_status("Tarama sürüyor", str(value), "active")
                    self._write(str(value))
                elif kind == "progress":
                    current, total = value
                    self.progress.set(current / total if total else 0)
                    self.progress_text.configure(text=f"{current:,} / {total:,} IP işlendi")
                elif kind == "done":
                    report_path, was_cancelled = value
                    self._finish_scan(Path(report_path), bool(was_cancelled))
                elif kind == "error":
                    self._finish_scan(None, False, str(value))
        except queue.Empty:
            pass
        self.after(100, self._consume_events)

    def _finish_scan(self, report_path: Path | None, was_cancelled: bool, error: str | None = None) -> None:
        self._is_scanning = False
        self._set_scan_controls(scanning=False)
        self._set_settings_controls(scanning=False)
        self._refresh_keys()
        self._scan_started_at = None
        self.elapsed.configure(text="")
        if error:
            self._set_status("Tarama hata ile durdu", error, "error")
            self._write(f"HATA: {error}")
            messagebox.showerror("Tarama tamamlanamadı", error, parent=self)
            return
        self._latest_report = report_path
        self.open_results.configure(state="normal")
        self.progress.set(1)
        self.progress_text.configure(text="İşlem tamamlandı")
        if was_cancelled:
            self._set_status("Tarama iptal edildi", f"Kısmi raporlar kaydedildi: {report_path}", "warning")
            self._write(f"Tarama iptal edildi. Kısmi raporlar oluşturuldu: {report_path}")
        else:
            self._set_status("Tarama tamamlandı", f"Özet ve detaylı raporlar hazır: {report_path}", "success")
            self._write(f"Raporlar oluşturuldu: {report_path}")

    def _set_scan_controls(self, scanning: bool) -> None:
        self.start.configure(state="disabled" if scanning else "normal")
        self.cancel.configure(state="normal" if scanning else "disabled", text="İptal İsteği")
        state = "disabled" if scanning else "normal"
        for widget in (self.input_button, self.paste_input, self.paste_button, self.output_button, self.score_entry, self.days_entry):
            widget.configure(state=state)

    def _set_settings_controls(self, scanning: bool) -> None:
        state = "disabled" if scanning else "normal"
        for widget in self._settings_controls:
            widget.configure(state=state)
        for button in self._key_action_buttons:
            button.configure(state=state)

    def _set_status(self, title: str, detail: str, tone: str) -> None:
        colors = {"neutral": MUTED, "active": ACCENT, "success": SUCCESS, "warning": WARNING, "error": DANGER}
        self.status_indicator.configure(text_color=colors.get(tone, MUTED))
        self.status_title.configure(text=title)
        self.status_detail.configure(text=detail)

    def _update_elapsed(self) -> None:
        if self._is_scanning and self._scan_started_at is not None:
            seconds = int(time.monotonic() - self._scan_started_at)
            self.elapsed.configure(text=f"Geçen: {seconds // 60:02d}:{seconds % 60:02d}")
        self.after(1_000, self._update_elapsed)

    def _open_results(self) -> None:
        if not self._latest_report or not self._latest_report.is_dir():
            messagebox.showinfo("Sonuçlar", "Açılacak bir sonuç klasörü henüz yok.", parent=self)
            return
        try:
            if sys.platform == "darwin":
                subprocess.Popen(["open", str(self._latest_report)])
            elif os.name == "nt":
                os.startfile(str(self._latest_report))  # type: ignore[attr-defined]
            else:
                subprocess.Popen(["xdg-open", str(self._latest_report)])
        except OSError as error:
            messagebox.showerror("Klasör açılamadı", self._safe_error(error), parent=self)

    def _on_close(self) -> None:
        if self._is_scanning:
            messagebox.showinfo("Tarama sürüyor", "Önce İptal İsteği düğmesini kullanın. Kısmi raporlar kaydedildiğinde pencereyi kapatabilirsiniz.", parent=self)
            return
        self.destroy()

    def _write(self, text: str) -> None:
        self.console.configure(state="normal")
        self.console.insert("end", text + "\n")
        self._console_lines += 1
        if self._console_lines > MAX_CONSOLE_LINES:
            self.console.delete("1.0", f"{CONSOLE_TRIM_LINES + 1}.0")
            self._console_lines -= CONSOLE_TRIM_LINES
        self.console.see("end")
        self.console.configure(state="disabled")

    @staticmethod
    def _safe_error(error: BaseException) -> str:
        message = str(error).replace("\n", " ")
        for marker in ("Key: ", "key=", "api_key=", "token=", "authorization="):
            if marker.lower() in message.lower():
                return "İşlem güvenli olmayan bir hata ayrıntısı üretti; ayrıntı gizlendi."
        return message[:300]


if __name__ == "__main__":
    SentinelApp().mainloop()
