import os
import time
import hashlib
import requests
import sys
import threading
import queue
import itertools
import shutil
import ctypes
from ctypes import windll, c_int, byref
import json
import uuid
import webbrowser
import tempfile
from PIL import Image, ImageDraw, ImageTk
import pystray
from pystray import MenuItem as item
import tkinter as tk
from tkinter import ttk, Menu
from tkinter import font as tkfont
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from plyer import notification
import pyzipper
import pyperclip

try:
    ctypes.windll.shcore.SetProcessDpiAwareness(1)
except: pass

API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
DOWNLOADS_PATH = os.path.expanduser('~/Downloads')

APP_DATA = os.path.join(os.environ['LOCALAPPDATA'], 'VT_Monitor_Win11')
HISTORY_FILE = os.path.join(APP_DATA, 'data.json')

os.makedirs(os.path.dirname(HISTORY_FILE), exist_ok=True)

CONFIRMED_THREAT_THRESHOLD = 4
TRUSTED_VENDORS = {
    'Microsoft', 'Kaspersky', 'BitDefender', 'CrowdStrike', 'SentinelOne',
    'ESET-NOD32', 'Paloalto', 'Google', 'Trend Micro', 'Malwarebytes',
    'AhnLab', 'Cybereason'
}

scan_queue = queue.PriorityQueue()
counter = itertools.count()
history_lock = threading.Lock()
gui_app = None

def apply_mica_style(root):
    try:
        hwnd = windll.user32.GetParent(root.winfo_id())
        windll.dwmapi.DwmSetWindowAttribute(hwnd, 20, byref(c_int(1)), 4)
        windll.dwmapi.DwmSetWindowAttribute(hwnd, 33, byref(c_int(2)), 4)
        root.configure(bg='#202020')
    except: pass

def create_chevron_icons():
    size = 32
    target = 14
    img_right = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    dc = ImageDraw.Draw(img_right)
    dc.line([(12, 8), (20, 16), (12, 24)], fill=(160, 160, 160), width=3)
    img_right = img_right.resize((target, target), Image.Resampling.LANCZOS)
    img_down = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    dc = ImageDraw.Draw(img_down)
    dc.line([(8, 12), (16, 20), (24, 12)], fill=(255, 255, 255), width=3)
    img_down = img_down.resize((target, target), Image.Resampling.LANCZOS)
    return ImageTk.PhotoImage(img_right), ImageTk.PhotoImage(img_down)

def create_tray_icon():
    image = Image.new('RGB', (64, 64), (0, 0, 0))
    dc = ImageDraw.Draw(image)
    dc.ellipse((16, 16, 48, 48), fill=(0, 255, 128))
    return image

def send_alert(title, message):
    try:
        notification.notify(title=title, message=message, app_name='VT_Monitor_Win11', timeout=1)
    except: pass

def pixel_truncate(text, font, max_width):
    if font.measure(text) <= max_width:
        return text
    
    ellipsis = "..."
    target_width = max_width - font.measure(ellipsis)
    
    low = 0
    high = len(text)
    while low < high:
        mid = (low + high + 1) // 2
        if font.measure(text[:mid]) <= target_width:
            low = mid
        else:
            high = mid - 1
            
    return text[:low] + ellipsis

def get_password_from_console(filename):
    try:
        try: ctypes.windll.kernel32.FreeConsole()
        except: pass
        if ctypes.windll.kernel32.AllocConsole():
            sys.stdin = open("CONIN$", "r")
            sys.stdout = open("CONOUT$", "w")
            sys.stderr = open("CONOUT$", "w")
            os.system("cls")
            print("\nVT_Monitor_Win11")
            print(f"\n[LOCKED ARCHIVE] {filename}")
            print("Password:")
            print("> ", end="")
            pwd = input()
            sys.stdin.close()
            sys.stdout.close()
            sys.stderr.close()
            ctypes.windll.kernel32.FreeConsole()
            return pwd.strip()
    except: pass
    return None

def is_zip_encrypted(filepath):
    try:
        with pyzipper.AESZipFile(filepath) as zf:
            for info in zf.infolist():
                if info.flag_bits & 0x1: return True
        return False
    except: return False

class SessionLog:
    def __init__(self):
        self.sessions = []
        self.load()

    def load(self):
        if os.path.exists(HISTORY_FILE):
            try:
                with open(HISTORY_FILE, 'r') as f: self.sessions = json.load(f)
            except: self.sessions = []

    def save(self):
        with history_lock:
            with open(HISTORY_FILE, 'w') as f: json.dump(self.sessions, f, indent=4)

    def create_session(self, session_id, filename):
        entry = {
            "id": session_id,
            "filename": filename,
            "status": "Scanning...",
            "score_str": "",
            "score_val": 0,
            "detections": [], 
            "link": ""
        }
        with history_lock:
            self.sessions.insert(0, entry)
            if len(self.sessions) > 60: self.sessions.pop()
        self.save()
        if gui_app: gui_app.refresh_safe()

    def update_status(self, session_id, status, score_val=0, score_str="", detections=None, link=""):
        with history_lock:
            for s in self.sessions:
                if s['id'] == session_id:
                    s['status'] = status
                    s['score_val'] = score_val
                    if score_str: s['score_str'] = score_str
                    if detections is not None: s['detections'] = detections
                    if link: s['link'] = link
                    break
        self.save()
        if gui_app: gui_app.refresh_safe()

    def get_stats(self):
        threats = sum(1 for s in self.sessions if s['score_val'] > 0)
        total = len(self.sessions)
        return threats, total

session_log = SessionLog()

class ToolTip(object):
    def __init__(self, widget):
        self.widget = widget
        self.tipwindow = None

    def showtip(self, text, x_root, y_root):
        if self.tipwindow or not text: return
        self.tipwindow = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(1)
        tw.attributes('-topmost', True) 
        tw.wm_geometry(f"+{x_root+15}+{y_root+10}")
        label = tk.Label(tw, text=text, justify=tk.LEFT,
                         background="#2d2d2d", foreground="#ffffff",
                         relief=tk.SOLID, borderwidth=0,
                         font=("Segoe UI", 9))
        label.pack(ipadx=5, ipady=2)

    def hidetip(self):
        tw = self.tipwindow
        self.tipwindow = None
        if tw: tw.destroy()

class NativeDashboard:
    def __init__(self):
        self.root = tk.Tk()
        self.root.withdraw()
        self.root.overrideredirect(True)
        self.root.attributes('-topmost', True)
        self.root.configure(bg="#202020")
        
        self.root.update_idletasks()
        apply_mica_style(self.root)

        self.width = 600
        self.height = 650
        
        self.font = tkfont.Font(family="Segoe UI Variable Text", size=10)

        self.colors = {
            'danger': '#ff6666',
            'warn': '#ffb86c',
            'safe': '#50fa7b',
            'wait': '#6272a4',
            'vendor': '#ffffff',
            'trusted_vendor': '#33c3f0',
            'threat': '#ff5555'
        }

        self.tooltip = None
        self.item_fulltext_map = {} 

        self.setup_ui()
        self.root.bind("<FocusOut>", self.on_focus_out)
        self.root.bind("<Button-1>", self.on_click_inside)
        global gui_app
        gui_app = self

    def setup_ui(self):
        main = tk.Frame(self.root, bg="#202020", highlightthickness=0, borderwidth=0)
        main.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        self.icon_right, self.icon_down = create_chevron_icons()
        self.setup_tree_style()

        tk.Label(main, text="THREATS DETECTED", bg="#202020", fg="#ff6666", 
                 font=("Segoe UI Variable Text", 9, "bold")).pack(anchor="w", pady=(0, 5))
        
        frame_threats = tk.Frame(main, bg="#202020", highlightthickness=0, borderwidth=0)
        frame_threats.pack(fill=tk.BOTH, expand=True)

        self.tree_threats = ttk.Treeview(frame_threats, columns=("Status", "Score"), show='tree', style="Custom.Treeview")
        self.tree_threats.pack(fill=tk.BOTH, expand=True)
        
        self.main_col_width = 380 
        self.tree_threats.column("#0", width=self.main_col_width, anchor="w", stretch=True) 
        self.tree_threats.column("Status", width=120, anchor="e", stretch=False)
        self.tree_threats.column("Score", width=60, anchor="e", stretch=False)
        
        self.tree_threats.bind("<Double-1>", self.on_double_click)
        self.tree_threats.bind("<Motion>", self.on_mouse_move)

        tk.Label(main, text="CLEAN FILES", bg="#202020", fg="#6cc4ff", 
                 font=("Segoe UI Variable Text", 9, "bold")).pack(anchor="w", pady=(15, 5))

        frame_clean = tk.Frame(main, bg="#202020", height=150, highlightthickness=0, borderwidth=0)
        frame_clean.pack(fill=tk.X)
        frame_clean.pack_propagate(False)

        self.tree_clean = ttk.Treeview(frame_clean, columns=("Status", "Score"), show='tree', style="Custom.Treeview")
        self.tree_clean.pack(fill=tk.BOTH, expand=True)
        
        self.tree_clean.column("#0", width=self.main_col_width, anchor="w", stretch=True)
        self.tree_clean.column("Status", width=120, anchor="e", stretch=False)
        self.tree_clean.column("Score", width=60, anchor="e", stretch=False)
        
        self.tree_clean.bind("<Double-1>", self.on_double_click)
        self.tree_clean.bind("<Motion>", self.on_mouse_move)

        footer = tk.Frame(self.root, bg="#202020", height=30, highlightthickness=0, borderwidth=0)
        footer.pack(fill=tk.X, padx=15, pady=10)
        self.stats_label = tk.Label(footer, text="0 Threats / 0 Scanned", bg="#202020", fg="#888888", 
                                    font=("Segoe UI Variable Text", 9))
        self.stats_label.pack(side=tk.RIGHT)

        self.context_menu = Menu(self.root, tearoff=0, bg="#2d2d2d", fg="white", activebackground="#3d3d3d", borderwidth=0, font=("Segoe UI", 9))
        self.tooltip = ToolTip(self.root)

    def setup_tree_style(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.layout("Custom.Treeview.Item", [('Custom.Treeitem.padding', {'sticky': 'nswe', 'children': [('Custom.Treeitem.indicator', {'side': 'left', 'sticky': ''}), ('Custom.Treeitem.image', {'side': 'left', 'sticky': ''}), ('Custom.Treeitem.text', {'side': 'left', 'sticky': ''})]})])
        style.map("Custom.Treeview", background=[('selected', '#3A3A3A')])
        style.configure("Custom.Treeview", background="#202020", foreground="#ffffff", fieldbackground="#202020", rowheight=34, borderwidth=0, highlightthickness=0, font=("Segoe UI Variable Text", 10))

    def show(self):
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        x = sw - self.width - 20
        y = sh - self.height - 70
        self.root.geometry(f"{self.width}x{self.height}+{x}+{y}")
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force() 
        self.refresh()

    def hide(self):
        self.tooltip.hidetip()
        self.root.withdraw()

    def on_click_inside(self, event): pass
    def on_focus_out(self, event):
        if self.root.focus_displayof(): return
        self.root.after(100, self.hide)

    def on_mouse_move(self, event):
        tree = event.widget
        item_id = tree.identify_row(event.y)
        col = tree.identify_column(event.x)
        
        if item_id and col == '#0' and item_id in self.item_fulltext_map:
            full = self.item_fulltext_map[item_id]
            displayed = tree.item(item_id, 'text').strip()
            
            if displayed.endswith("...") and full not in displayed:
                 self.tooltip.showtip(full, event.x_root, event.y_root)
                 return
        self.tooltip.hidetip()

    def on_double_click(self, event):
        tree = event.widget
        try:
            item_id = tree.identify_row(event.y)
            if not item_id: return
            
            full_text = self.item_fulltext_map.get(item_id)
            if not full_text: 
                full_text = tree.item(item_id, "text").strip() # Fallback

            parent_id = tree.parent(item_id)
            if not parent_id:
                s = self.get_selected_session(item_id, tree)
                if s and s.get('link'): webbrowser.open(s['link'])
                elif s: pyperclip.copy(s['filename']) # Should be full name
            else:
                pyperclip.copy(full_text)
        except: pass

    def get_selected_session(self, item_id, tree):
        if item_id in self.item_fulltext_map:
            full_name = self.item_fulltext_map[item_id]
            for s in session_log.sessions:
                if s['filename'] == full_name: return s
        curr = item_id
        while tree.parent(curr): curr = tree.parent(curr)
        if curr in self.item_fulltext_map:
            full_name = self.item_fulltext_map[curr]
            for s in session_log.sessions:
                if s['filename'] == full_name: return s
        return None

    def refresh_safe(self):
        self.root.after(0, self.refresh)

    def refresh(self):
        for i in self.tree_threats.get_children(): self.tree_threats.delete(i)
        for i in self.tree_clean.get_children(): self.tree_clean.delete(i)
        self.item_fulltext_map.clear()

        W_ROOT = self.main_col_width - 30
        W_CHILD = W_ROOT - 20 
        W_GRANDCHILD = W_CHILD - 20

        with history_lock:
            for s in session_log.sessions:
                score_val = s['score_val']
                status = s['status']
                
                display_name = pixel_truncate(s['filename'], self.font, W_ROOT)

                if score_val > 0:
                    tag = 'danger' if score_val >= CONFIRMED_THREAT_THRESHOLD else 'warn'
                    
                    file_node = self.tree_threats.insert("", "end", text=f" {display_name}", 
                                                         values=(status, s['score_str']),
                                                         open=False, tags=(tag,))
                    self.item_fulltext_map[file_node] = s['filename']
                    
                    if s['detections']:
                        for vendor, threat_name in s['detections']:
                            is_trusted = vendor in TRUSTED_VENDORS
                            vendor_tag = 'trusted_vendor' if is_trusted else 'vendor'
                            
                            disp_vendor = pixel_truncate(vendor, self.font, W_CHILD)
                            disp_threat = pixel_truncate(threat_name, self.font, W_GRANDCHILD)
                            
                            vendor_node = self.tree_threats.insert(file_node, "end", text=f" {disp_vendor}", tags=(vendor_tag,))
                            self.item_fulltext_map[vendor_node] = vendor
                            
                            threat_node = self.tree_threats.insert(vendor_node, "end", text=f"    {disp_threat}", tags=('threat',))
                            self.item_fulltext_map[threat_node] = threat_name
                else:
                    tag = 'wait' if "Scanning" in status else 'safe'
                    file_node = self.tree_clean.insert("", "end", text=f" {display_name}", 
                                           values=(status, s['score_str']),
                                           tags=(tag,))
                    self.item_fulltext_map[file_node] = s['filename']

        for tree in [self.tree_threats, self.tree_clean]:
            tree.tag_configure('danger', foreground=self.colors['danger']) 
            tree.tag_configure('warn', foreground=self.colors['warn'])
            tree.tag_configure('safe', foreground=self.colors['safe'])
            tree.tag_configure('wait', foreground=self.colors['wait'])
            tree.tag_configure('vendor', foreground=self.colors['vendor']) 
            tree.tag_configure('trusted_vendor', foreground=self.colors['trusted_vendor']) 
            tree.tag_configure('threat', foreground=self.colors['threat'])
        
        t, tot = session_log.get_stats()
        self.stats_label.config(text=f"{t} Threats / {tot} Scanned")

    def run(self):
        self.root.mainloop()

class ScanEngine(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.start()

    def run(self):
        while True:
            _, _, filepath, session_id = scan_queue.get()
            try:
                if os.path.exists(filepath): self.analyze(filepath, session_id)
            except Exception as e:
                err = str(e)
                if len(err) > 30: err = err[:27] + "..."
                session_log.update_status(session_id, "Error", 0, err)
            finally: scan_queue.task_done()

    def analyze(self, filepath, session_id):
        filename = os.path.basename(filepath)
        if not self.wait_for_file(filepath): return
        fhash = self.get_hash(filepath)
        if not fhash: return

        if filename.lower().endswith('.zip') and is_zip_encrypted(filepath):
            session_log.update_status(session_id, "Locked Zip")
            pwd = get_password_from_console(filename)
            if pwd:
                try:
                    with tempfile.TemporaryDirectory() as temp_dir:
                        with pyzipper.AESZipFile(filepath) as zf:
                            zf.extractall(path=temp_dir, pwd=pwd.encode('utf-8'))
                        found_threats = False
                        for root, dirs, files in os.walk(temp_dir):
                            for file in files:
                                inner_hash = self.get_hash(os.path.join(root, file))
                                if inner_hash:
                                    report = self.query_vt(inner_hash)
                                    if report and self.check_bad(report):
                                        self.process(filepath, report, session_id)
                                        found_threats = True
                                        break
                            if found_threats: break
                        if not found_threats:
                            session_log.update_status(session_id, "Clean", 0, "0/0", [], "")
                except Exception as e:
                    session_log.update_status(session_id, "Error", 0, str(e)[:20])
            return

        report = self.query_vt(fhash)
        if report:
            self.process(filepath, report, session_id)
        else:
            self.upload(filepath, filename, session_id)

    def check_bad(self, report):
        return report.get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0) > 0

    def process(self, filepath, report, session_id):
        stats = report.get('attributes', {}).get('last_analysis_stats', {})
        results = report.get('attributes', {}).get('last_analysis_results', {})
        malicious = stats.get('malicious', 0)
        total = sum(stats.values())
        link = f"https://www.virustotal.com/gui/file/{report['attributes']['sha256']}"
        det_data = []
        for vendor, res in results.items():
            if res['category'] == 'malicious':
                det_data.append((vendor, res['result']))
        
        trusted = sorted([d for d in det_data if d[0] in TRUSTED_VENDORS], key=lambda x: x[0])
        others = sorted([d for d in det_data if d[0] not in TRUSTED_VENDORS], key=lambda x: x[0])
        final_dets = trusted + others

        score_str = f"{malicious}/{total}"
        if malicious >= CONFIRMED_THREAT_THRESHOLD:
            session_log.update_status(session_id, "Critical Threat", malicious, score_str, final_dets, link)
            send_alert("CRITICAL THREAT", f"{os.path.basename(filepath)} detected!")
        elif malicious > 0:
            session_log.update_status(session_id, "Suspicious", malicious, score_str, final_dets, link)
            send_alert("Suspicious File", "Check tray details")
        else:
            session_log.update_status(session_id, "Clean", 0, score_str, [], link)

    def query_vt(self, h):
        try:
            r = requests.get(f"https://www.virustotal.com/api/v3/files/{h}", headers={'x-apikey': API_KEY})
            if r.status_code == 200: return r.json()['data']
        except: pass
        return None

    def upload(self, filepath, filename, session_id):
        session_log.update_status(session_id, "Uploading...")
        try:
            file_size_mb = os.path.getsize(filepath) / (1024 * 1024)
            if file_size_mb > 650:
                session_log.update_status(session_id, "Too Large")
                return
            upload_url = "https://www.virustotal.com/api/v3/files"
            if file_size_mb >= 32:
                r = requests.get(f"{upload_url}/upload_url", headers={'x-apikey': API_KEY})
                if r.status_code == 200: upload_url = r.json().get('data')
            with open(filepath, 'rb') as f:
                r = requests.post(upload_url, headers={'x-apikey': API_KEY}, files={'file': (filename, f)})
            if r.status_code == 200:
                analysis_id = r.json()['data']['id']
                link = f"https://www.virustotal.com/gui/file-analysis/{analysis_id}"
                session_log.update_status(session_id, "Analyzing...", 0, "", [], link)
                threading.Thread(target=self.poll_analysis, args=(analysis_id, filepath, session_id), daemon=True).start()
            else:
                session_log.update_status(session_id, "Upload Failed")
        except:
            session_log.update_status(session_id, "Error")

    def poll_analysis(self, analysis_id, filepath, session_id):
        url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        headers = {'x-apikey': API_KEY}
        for _ in range(60): 
            time.sleep(15)
            try:
                r = requests.get(url, headers=headers)
                if r.status_code == 200:
                    data = r.json()['data']['attributes']
                    if data.get('status') == 'completed':
                        fake_report = {
                            'attributes': {
                                'last_analysis_stats': data['stats'],
                                'last_analysis_results': data['results'],
                                'sha256': data.get('meta', {}).get('file_info', {}).get('sha256', 'unknown')
                            }
                        }
                        self.process(filepath, fake_report, session_id)
                        return
            except: pass
        session_log.update_status(session_id, "Timed Out")

    def get_hash(self, path):
        h = hashlib.sha256()
        try:
            with open(path, 'rb') as f: h.update(f.read())
            return h.hexdigest()
        except: return None

    def wait_for_file(self, path):
        for _ in range(60):
            try:
                with open(path, 'ab'): pass
                return True
            except: time.sleep(0.5)
        return False

def run_tray():
    def toggle(icon, item):
        if gui_app: gui_app.root.after(0, gui_app.show)
    def exit_app(icon, item): icon.stop(); os._exit(0)
    menu = (item('Show Monitor', toggle, default=True), item('Exit', exit_app))
    pystray.Icon("VT", create_tray_icon(), "VT_Monitor_Win11", menu).run()

class TrayWatcher(FileSystemEventHandler):
    def on_created(self, event): self.p(event)
    def on_moved(self, event): 
        if not event.is_directory: self.q(event.dest_path)
    def p(self, event):
        if not event.is_directory: self.q(event.src_path)
    def q(self, fp):
        fn = os.path.basename(fp)
        if fn.endswith(('.crdownload', '.tmp', '.lock')): return
        sid = str(uuid.uuid4())[:8]
        session_log.create_session(sid, fn)
        scan_queue.put((3, next(counter), fp, sid))

if __name__ == "__main__":
    ScanEngine()
    observer = Observer()
    observer.schedule(TrayWatcher(), DOWNLOADS_PATH, recursive=False)
    observer.start()
    send_alert("Active", "Monitor Mode")
    threading.Thread(target=run_tray, daemon=True).start()
    app = NativeDashboard()
    app.run()
