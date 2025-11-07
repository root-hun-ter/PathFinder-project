#!/usr/bin/env python3
# pathfinder_gui.py
# By RootHunter — GitHub / Facebook / Instagram

import threading
import requests
import time
import json
import csv
import webbrowser
from queue import Queue, Empty
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# ---------- Configuration ----------
DEFAULT_WORDS = [
    "admin", "login", "dashboard", "backup", "bak", "old", "test", "dev",
    "config", "wp-admin", "wp-login.php", "robots.txt", "sitemap.xml",
    ".git", ".env", "phpinfo.php", "server-status", "api", "uploads",
    "uploads_old", "logs", "shell", "backup.zip", "db_backup.sql"
]

USER_AGENT = "PathFinder-GUI/1.0 (by RootHunter)"

# Developer/social links (يمكن تعديلها)
DEV_NAME = "RootHunter"
GITHUB = "https://github.com/RootHunter"
FACEBOOK = "https://facebook.com/RootHunter"
INSTAGRAM = "https://instagram.com/RootHunter"

# ---------- Networking helpers (synchronous, safe GET only) ----------
session = requests.Session()
session.headers.update({"User-Agent": USER_AGENT})
session.verify = True
REQUEST_TIMEOUT = 12

def norm_url(base, path):
    if path.startswith("http://") or path.startswith("https://"):
        return path
    return urljoin(base, path)

def same_origin(a, b):
    pa = urlparse(a)
    pb = urlparse(b)
    return (pa.scheme, pa.netloc) == (pb.scheme, pb.netloc)

def fetch_url(url, verify_ssl=True):
    try:
        r = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        return {"url": r.url, "status": r.status_code, "text": r.text, "headers": dict(r.headers)}
    except Exception as e:
        return {"url": url, "error": str(e)}

def fetch_robots(base):
    robots_url = norm_url(base, "/robots.txt")
    r = fetch_url(robots_url)
    paths = []
    if r.get("status") == 200:
        for line in r["text"].splitlines():
            line = line.strip()
            if not line or line.startswith("#"): continue
            if line.lower().startswith("disallow:"):
                parts = line.split(":",1)
                if len(parts) > 1:
                    p = parts[1].strip()
                    if p:
                        paths.append(norm_url(base, p))
    return paths, r

def fetch_sitemap(base):
    sitemap_url = norm_url(base, "/sitemap.xml")
    r = fetch_url(sitemap_url)
    urls = []
    if r.get("status") == 200:
        for m in BeautifulSoup(r["text"], "xml").find_all("loc"):
            try:
                urls.append(m.text.strip())
            except Exception:
                pass
    return urls, r

def extract_links(base, html):
    soup = BeautifulSoup(html or "", "html.parser")
    urls = set()
    for tag, attr in (("a","href"), ("link","href"), ("script","src"), ("img","src"), ("iframe","src")):
        for t in soup.find_all(tag):
            v = t.get(attr)
            if not v: continue
            full = norm_url(base, v.split('#')[0])
            urls.add(full)
    # forms (GET)
    for form in soup.find_all("form"):
        method = (form.get("method") or "get").lower()
        action = form.get("action") or ""
        if method == "get":
            urls.add(norm_url(base, action))
    return urls

def extract_parameters(urls):
    params = {}
    for u in urls:
        q = urlparse(u).query
        if not q: continue
        parsed = parse_qs(q)
        for k,v in parsed.items():
            if k not in params:
                params[k] = set()
            for vv in v:
                params[k].add(vv)
    return {k: list(v) for k,v in params.items()}

# ---------- Worker thread ----------
class PathfinderWorker(threading.Thread):
    def __init__(self, target, words, options, queue_updates):
        super().__init__(daemon=True)
        self.target = target
        self.words = words
        self.options = options
        self.queue = queue_updates
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def stopped(self):
        return self._stop.is_set()

    def run(self):
        try:
            if not self.target.startswith("http://") and not self.target.startswith("https://"):
                target = "https://" + self.target
            else:
                target = self.target
            parsed = urlparse(target)
            base = f"{parsed.scheme}://{parsed.netloc}"
            self.queue.put(("log", f"[*] Starting scan for {base}"))
            results = {"target": base, "found": [], "robots": [], "sitemap": [], "pages": [], "links": [], "params": {}}

            # robots
            if self.options.get("robots"):
                self.queue.put(("log", "[*] Fetching robots.txt ..."))
                robots_paths, robots_raw = fetch_robots(base)
                results["robots"] = robots_paths
                self.queue.put(("robots", robots_paths))
                self.queue.put(("log", f"[+] robots: {len(robots_paths)} entries"))

            # sitemap
            if self.options.get("sitemap"):
                self.queue.put(("log", "[*] Fetching sitemap.xml ..."))
                s_urls, sitemap_raw = fetch_sitemap(base)
                results["sitemap"] = s_urls
                self.queue.put(("sitemap", s_urls))
                self.queue.put(("log", f"[+] sitemap: {len(s_urls)} urls"))

            # crawl (shallow)
            max_pages = int(self.options.get("max_pages", 50))
            visited = set()
            to_visit = [base]
            collected_links = set()
            collected_pages = []
            self.queue.put(("log", "[*] Starting shallow crawl ..."))
            while to_visit and len(visited) < max_pages and not self.stopped():
                url = to_visit.pop(0)
                if url in visited: continue
                visited.add(url)
                r = fetch_url(url, verify_ssl=not self.options.get("insecure"))
                if r.get("status") == 200:
                    links = extract_links(url, r["text"])
                    for l in links:
                        if same_origin(base, l) and l not in visited:
                            to_visit.append(l)
                    collected_links.update(links)
                    collected_pages.append({"url": url, "status": r["status"]})
                self.queue.put(("progress", len(visited)))
            results["pages"] = collected_pages
            results["links"] = list(collected_links)
            self.queue.put(("log", f"[+] Crawl done: visited {len(visited)} pages, found {len(collected_links)} links"))

            # candidates: combine robots, sitemap, links, and wordlist
            candidates = set()
            candidates.update(results["robots"])
            candidates.update(results["sitemap"])
            candidates.update(results["links"])
            candidates.add(base)
            for w in self.words:
                candidates.add(norm_url(base, "/" + w.lstrip("/")))

            # fuzzing / checking candidates with concurrency
            self.queue.put(("log", "[*] Checking candidate URLs (safe GET only) ..."))
            found = []
            total = len(candidates)
            checked = 0
            # simple thread pool using requests (synchronous)
            from concurrent.futures import ThreadPoolExecutor, as_completed
            concurrency = int(self.options.get("concurrency", 10))
            with ThreadPoolExecutor(max_workers=concurrency) as ex:
                future_map = {ex.submit(fetch_url, u,): u for u in candidates}
                for fut in as_completed(future_map):
                    if self.stopped():
                        break
                    u = future_map[fut]
                    try:
                        r = fut.result()
                    except Exception as e:
                        r = {"url": u, "error": str(e)}
                    checked += 1
                    # progress
                    self.queue.put(("candidate_progress", (checked, total)))
                    if r.get("status") and r["status"] < 400:
                        found.append({"url": r["url"], "status": r["status"]})
                        self.queue.put(("found", {"url": r["url"], "status": r["status"]}))
                    elif r.get("status") and r["status"] >= 400:
                        # include for completeness as "warning" (4xx/5xx)
                        self.queue.put(("warning", {"url": r.get("url"), "status": r.get("status")}))
                    elif r.get("error"):
                        # network error -> log as error
                        self.queue.put(("error", {"url": r.get("url"), "error": r.get("error")}))
            results["found"] = found

            # parameter extraction
            results["params"] = extract_parameters(results["links"])

            # finish
            self.queue.put(("done", results))
            self.queue.put(("log", "[+] Scan finished."))
        except Exception as e:
            self.queue.put(("error", {"url": self.target, "error": str(e)}))

# ---------- GUI ----------
class PathFinderGUI:
    def __init__(self, root):
        self.root = root
        root.title("PathFinder — by RootHunter")
        root.geometry("900x700")
        root.minsize(800,600)
        # styles
        self.style = ttk.Style()
        try:
            self.style.theme_use("clam")
        except Exception:
            pass

        # Top frame: inputs
        top = ttk.Frame(root, padding=(10,10))
        top.pack(fill="x")
        ttk.Label(top, text="Target (domain or URL):").grid(row=0, column=0, sticky="w")
        self.entry_target = ttk.Entry(top, width=60)
        self.entry_target.grid(row=0, column=1, columnspan=3, sticky="w", padx=6)
        self.entry_target.insert(0, "example.com")

        ttk.Label(top, text="Concurrency:").grid(row=1, column=0, sticky="w", pady=(6,0))
        self.spin_conc = ttk.Spinbox(top, from_=1, to=50, width=6)
        self.spin_conc.set(10)
        self.spin_conc.grid(row=1, column=1, sticky="w", pady=(6,0))

        self.chk_robots = tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text="Fetch robots.txt", variable=self.chk_robots).grid(row=1, column=2, sticky="w")
        self.chk_sitemap = tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text="Fetch sitemap.xml", variable=self.chk_sitemap).grid(row=1, column=3, sticky="w")

        # Wordlist selectors
        wl_frame = ttk.LabelFrame(root, text="Wordlist", padding=(10,8))
        wl_frame.pack(fill="x", padx=10, pady=(6,0))
        self.use_default_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(wl_frame, text="Use default built-in wordlist", variable=self.use_default_var, command=self._toggle_wl).grid(row=0, column=0, sticky="w")
        ttk.Button(wl_frame, text="Load custom wordlist file...", command=self.load_wordlist_file).grid(row=0, column=1, sticky="e")
        self.lbl_wl_file = ttk.Label(wl_frame, text="(no file loaded)")
        self.lbl_wl_file.grid(row=1, column=0, columnspan=2, sticky="w", pady=(6,0))
        self.custom_words = []

        # Action buttons
        btn_frame = ttk.Frame(root, padding=(10,6))
        btn_frame.pack(fill="x")
        self.btn_start = ttk.Button(btn_frame, text="Start Scan", command=self.start_scan)
        self.btn_start.pack(side="left")
        self.btn_stop = ttk.Button(btn_frame, text="Stop", command=self.stop_scan, state="disabled")
        self.btn_stop.pack(side="left", padx=6)
        ttk.Button(btn_frame, text="Save Results (JSON)", command=self.save_results_json).pack(side="right")
        ttk.Button(btn_frame, text="Save Results (CSV)", command=self.save_results_csv).pack(side="right", padx=6)

        # Progress bar and status
        progress_frame = ttk.Frame(root, padding=(10,6))
        progress_frame.pack(fill="x")
        self.progress = ttk.Progressbar(progress_frame, mode="determinate")
        self.progress.pack(fill="x", side="left", expand=True)
        self.lbl_status = ttk.Label(progress_frame, text="Idle")
        self.lbl_status.pack(side="left", padx=8)

        # Middle: results treeview
        mid_frame = ttk.Frame(root, padding=(10,6))
        mid_frame.pack(fill="both", expand=True)
        cols = ("status", "url")
        self.tree = ttk.Treeview(mid_frame, columns=cols, show="headings", selectmode="browse")
        self.tree.heading("status", text="Status")
        self.tree.heading("url", text="URL")
        self.tree.column("status", width=80, anchor="center")
        self.tree.column("url", width=700, anchor="w")
        self.tree.pack(fill="both", expand=True, side="left")
        # attach vertical scrollbar
        vsb = ttk.Scrollbar(mid_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=vsb.set)
        vsb.pack(side="left", fill="y")

        # Color tags using tag_configure (ttk treeview uses tag styles via tags)
        self.tree.tag_configure("found", background="#e6ffea")    # pale green
        self.tree.tag_configure("warning", background="#fff4e0")  # pale orange
        self.tree.tag_configure("error", background="#ffeaea")    # pale red
        self.tree.tag_configure("info", background="#e8f0ff")     # pale blue

        # Bottom: log text + developer info
        bottom = ttk.Frame(root, padding=(10,6))
        bottom.pack(fill="x")
        # log text
        self.txt_log = tk.Text(bottom, height=8, wrap="word", state="disabled")
        self.txt_log.pack(fill="both", expand=True, side="left")
        log_vsb = ttk.Scrollbar(bottom, orient="vertical", command=self.txt_log.yview)
        self.txt_log.configure(yscroll=log_vsb.set)
        log_vsb.pack(side="left", fill="y")

        # developer info
        dev_frame = ttk.Frame(root, padding=(10,6))
        dev_frame.pack(fill="x")
        ttk.Label(dev_frame, text=f"PathFinder — by {DEV_NAME}", font=("Segoe UI", 10, "bold")).pack(side="left")
        ttk.Button(dev_frame, text="GitHub", command=lambda: webbrowser.open(GITHUB)).pack(side="right")
        ttk.Button(dev_frame, text="Instagram", command=lambda: webbrowser.open(INSTAGRAM)).pack(side="right", padx=4)
        ttk.Button(dev_frame, text="Facebook", command=lambda: webbrowser.open(FACEBOOK)).pack(side="right", padx=4)

        # internal state
        self.worker = None
        self.queue = Queue()
        self.results = None

        # schedule queue processing
        root.after(200, self._process_queue)

    def _toggle_wl(self):
        if self.use_default_var.get():
            self.lbl_wl_file.configure(text="(using built-in default wordlist)")
        else:
            if self.custom_words:
                self.lbl_wl_file.configure(text=f"Loaded: {len(self.custom_words)} words")
            else:
                self.lbl_wl_file.configure(text="(no file loaded)")

    def load_wordlist_file(self):
        path = filedialog.askopenfilename(title="Select wordlist file", filetypes=[("Text files","*.txt"),("All files","*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            self.custom_words = words
            self.use_default_var.set(False)
            self.lbl_wl_file.configure(text=f"Loaded: {len(words)} words ({Path(path).name})")
            self._log(f"[+] Loaded custom wordlist: {len(words)} words")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load wordlist: {e}")

    def start_scan(self):
        target = self.entry_target.get().strip()
        if not target:
            messagebox.showwarning("Input required", "Please enter a target domain or URL.")
            return
        if self.worker and self.worker.is_alive():
            messagebox.showinfo("Already running", "A scan is already in progress.")
            return
        # prepare words
        if self.use_default_var.get():
            words = DEFAULT_WORDS.copy()
        else:
            words = self.custom_words.copy() if self.custom_words else DEFAULT_WORDS.copy()
        options = {
            "robots": self.chk_robots.get(),
            "sitemap": self.chk_sitemap.get(),
            "concurrency": int(self.spin_conc.get()),
            "max_pages": 50,
            "insecure": False
        }
        # clear UI
        for i in self.tree.get_children():
            self.tree.delete(i)
        self._set_status("Running")
        self.progress["value"] = 0
        self.progress["maximum"] = 100
        # start worker
        self.worker = PathfinderWorker(target, words, options, self.queue)
        self.worker.start()
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self._log(f"[*] Scan started for {target} (words={len(words)})")

    def stop_scan(self):
        if self.worker:
            self.worker.stop()
            self._log("[!] Stop requested (will finish in-progress requests)...")
            self.btn_stop.configure(state="disabled")

    def save_results_json(self):
        if not self.results:
            messagebox.showinfo("No results", "No results to save.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files","*.json")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            messagebox.showinfo("Saved", f"Results saved to {path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save: {e}")

    def save_results_csv(self):
        if not self.results:
            messagebox.showinfo("No results", "No results to save.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files","*.csv")])
        if not path:
            return
        try:
            rows = []
            for item in self.results.get("found", []):
                rows.append((item.get("url"), item.get("status")))
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["url","status"])
                w.writerows(rows)
            messagebox.showinfo("Saved", f"CSV saved to {path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save: {e}")

    def _log(self, msg):
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        self.txt_log.configure(state="normal")
        self.txt_log.insert("end", f"[{ts}] {msg}\n")
        self.txt_log.see("end")
        self.txt_log.configure(state="disabled")

    def _process_queue(self):
        try:
            while True:
                item = self.queue.get_nowait()
                typ = item[0]
                payload = item[1]
                if typ == "log":
                    self._log(payload)
                elif typ == "robots":
                    # could update UI
                    pass
                elif typ == "sitemap":
                    pass
                elif typ == "progress":
                    # crawl progress count
                    self.lbl_status.configure(text=f"Crawled {payload} pages")
                elif typ == "candidate_progress":
                    checked, total = payload
                    pct = int((checked/total)*100) if total else 0
                    self.progress["value"] = pct
                    self.lbl_status.configure(text=f"Checking candidates ({checked}/{total})")
                elif typ == "found":
                    u = payload
                    self.tree.insert("", "end", values=(u["status"], u["url"]), tags=("found",))
                elif typ == "warning":
                    u = payload
                    self.tree.insert("", "end", values=(u.get("status","?"), u.get("url","")), tags=("warning",))
                elif typ == "error":
                    u = payload
                    self.tree.insert("", "end", values=(u.get("error","err"), u.get("url","")), tags=("error",))
                elif typ == "done":
                    self.results = payload
                    self._log("[+] Results ready")
                    self._set_status("Idle")
                    self.progress["value"] = 100
                    self.btn_start.configure(state="normal")
                    self.btn_stop.configure(state="disabled")
                else:
                    # general info
                    self._log(repr(item))
        except Empty:
            pass
        # schedule next check
        self.root.after(200, self._process_queue)

    def _set_status(self, s):
        self.lbl_status.configure(text=s)

def main():
    root = tk.Tk()
    app = PathFinderGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
