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
from concurrent.futures import ThreadPoolExecutor
from PIL import Image, ImageDraw, ImageTk
import pystray
from pystray import MenuItem as item
import tkinter as tk
from tkinter import ttk, Menu, filedialog
from tkinter import font as tkfont
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import pyzipper
import pyperclip
import collections

try:
    myappid = 'vt3.monitor.app.1.0'
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
    ctypes.windll.shcore.SetProcessDpiAwareness(1)
except: pass

API_KEY = None
DOWNLOADS_PATH = os.path.expanduser('~/Downloads')
APP_DATA = os.path.join(os.environ['LOCALAPPDATA'], 'VT3_Monitor_Win11')
HISTORY_FILE = os.path.join(APP_DATA, 'data.json')
CONFIG_FILE = os.path.join(APP_DATA, 'config.json')

os.makedirs(os.path.dirname(HISTORY_FILE), exist_ok=True)

CONFIRMED_THREAT_THRESHOLD = 4
MAX_FILE_SIZE_MB = 650
TRUSTED_VENDORS = {
    'Microsoft', 'Kaspersky', 'BitDefender', 'CrowdStrike', 'SentinelOne',
    'ESET-NOD32', 'Paloalto', 'Google', 'Trend Micro', 
    'Malwarebytes', 'AhnLab', 'Cybereason'
}

scan_queue = queue.PriorityQueue()
counter = itertools.count()
history_lock = threading.Lock()
upload_semaphore = threading.Semaphore(3) 
gui_app = None
tray_icon = None
HASH_ONLY_MODE = False
scan_engine_ref = None

def is_api_key_valid(key):
    url = "https://www.virustotal.com/api/v3/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    try:
        r = requests.get(url, headers={'x-apikey': key}, timeout=10)
        return r.status_code != 401
    except:
        return True

def load_or_setup_api_key():
    global API_KEY
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                data = json.load(f)
                if data.get('api_key'):
                    API_KEY = data['api_key']
                    return
        except: pass

    try:
        try: ctypes.windll.kernel32.FreeConsole()
        except: pass
        if ctypes.windll.kernel32.AllocConsole():
            sys.stdin = open("CONIN$", "r")
            sys.stdout = open("CONOUT$", "w")
            sys.stderr = open("CONOUT$", "w")
            ctypes.windll.kernel32.SetConsoleTitleW("VT3 Monitor - Setup")
            os.system("cls")
            print("\n" + "="*50)
            print("      VIRUSTOTAL3 MONITOR")
            print("      FIRST RUN SETUP")
            print("="*50 + "\n")
            print("  This tool requires a VirusTotal3 API key.")
            print("  1. Go to: https://www.virustotal.com/gui/my-apikey")
            print("  2. Copy your API Key and paste it below and press ENTER")
            while not API_KEY:
                print("\n  Paste API Key > ", end="")
                user_input = input().strip()
                if len(user_input) > 30:
                    print("  [~] Verifying API Key...")
                    if is_api_key_valid(user_input):
                        API_KEY = user_input
                        try:
                            with open(CONFIG_FILE, 'w') as f:
                                json.dump({'api_key': API_KEY}, f)
                            print("\n  [+] SUCCESS: API Key verified and saved.")
                            print("  [+] Starting Monitor...")
                            time.sleep(2)
                        except Exception as e:
                            print(f"\nError saving config: {e}")
                            time.sleep(5)
                    else:
                        print("  [-] ERROR: API Key rejected by VirusTotal3 (401 Unauthorized).")
                else:
                    print("Invalid Key length. Please try again.")
            sys.stdin.close()
            sys.stdout.close()
            sys.stderr.close()
            ctypes.windll.kernel32.FreeConsole()
    except Exception as e:
        ctypes.windll.user32.MessageBoxW(0, f"Setup Error: {str(e)}", "VT3 Monitor Error", 0x10)
        sys.exit(1)
    if not API_KEY: sys.exit(0)

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
        if tray_icon:
            tray_icon.notify(message, title)
    except: pass

def pixel_truncate(text, font, max_width):
    if not text: return ""
    if font.measure(text) <= max_width: return text
    ellipsis = "..."
    target_width = max_width - font.measure(ellipsis)
    if target_width <= 0: return ellipsis
    low = 0
    high = len(text)
    best = 0
    while low <= high:
        mid = (low + high) // 2
        if font.measure(text[:mid]) <= target_width:
            best = mid
            low = mid + 1
        else:
            high = mid - 1
    return text[:best] + ellipsis

def get_password_from_console(filename):
    try:
        try: ctypes.windll.kernel32.FreeConsole()
        except: pass
        if ctypes.windll.kernel32.AllocConsole():
            sys.stdin = open("CONIN$", "r")
            sys.stdout = open("CONOUT$", "w")
            sys.stderr = open("CONOUT$", "w")
            ctypes.windll.kernel32.SetConsoleTitleW("VT3 Monitor - Locked Archive Password")
            os.system("cls")
            print(f"\n[LOCKED ARCHIVE] {filename}")
            print("\n  Password > ", end="")
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

def set_startup(enable=True):
    startup_folder = os.path.join(os.getenv('APPDATA'), r'Microsoft\Windows\Start Menu\Programs\Startup')
    target_name = "VT3_Monitor_Win11.exe"
    destination = os.path.join(startup_folder, target_name)

    try:
        if enable:
            if getattr(sys, 'frozen', False):
                shutil.copy2(sys.executable, destination)
                send_alert("System", "Startup Enabled")
            else:
                print("Startup logic skipped: Not running as a frozen executable.")
        else:
            if os.path.exists(destination):
                os.remove(destination)
                send_alert("System", "Startup Disabled")
    except Exception as e:
        send_alert("Error", "Could not change startup settings")
        
def check_startup():
    startup_folder = os.path.join(os.getenv('APPDATA'), r'Microsoft\Windows\Start Menu\Programs\Startup')
    target_name = "VT3_Monitor_Win11.exe"
    destination = os.path.join(startup_folder, target_name)
    return os.path.exists(destination)

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

    def create_session(self, session_id, filename, filepath):
        entry = {
            "id": session_id,
            "filename": filename,
            "filepath": filepath,
            "status": "Scanning...",
            "score_str": "",
            "score_val": 0,
            "detections": [], 
            "link": "",
            "is_container": False,
            "children": [] 
        }
        with history_lock:
            self.sessions.insert(0, entry)
            if len(self.sessions) > 60: self.sessions.pop()
        self.save()
        if gui_app: gui_app.refresh_safe()

    def update_status(self, session_id, status, score_val=0, score_str="", detections=None, link="", children=None):
        with history_lock:
            for s in self.sessions:
                if s['id'] == session_id:
                    s['status'] = status
                    s['score_val'] = score_val
                    if score_str: s['score_str'] = score_str
                    if detections is not None: s['detections'] = detections
                    if link: s['link'] = link
                    if children is not None: 
                        s['children'] = children
                        s['is_container'] = True
                    break
        self.save()
        if gui_app: gui_app.refresh_safe()

    def update_child_status(self, parent_id, child_filename, status, score_str):
        with history_lock:
            for s in self.sessions:
                if s['id'] == parent_id:
                    if 'children' in s:
                        for c in s['children']:
                            if c['filename'] == child_filename:
                                c['status'] = status
                                c['score_str'] = score_str
                                break
                    break
        self.save()
        if gui_app: gui_app.refresh_safe()

    def get_stats(self):
        threats = sum(1 for s in self.sessions if s['score_val'] > 0 or any(c.get('score_val', 0) > 0 for c in s.get('children', [])))
        total = len(self.sessions)
        return threats, total

session_log = SessionLog()

# --- GUI ---
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
            'danger': '#ff6666', 'warn': '#ffb86c', 'safe': '#50fa7b', 'wait': '#6272a4',
            'vendor': '#ffffff', 'trusted_vendor': '#33c3f0', 'threat': '#ff5555', 
            'child_file': '#dddddd', 'action': '#ffffff'
        }
        self.tooltip = None
        self.item_fulltext_map = {} 
        self.item_status_map = {}
        self.item_session_map = {} 
        self._pending_refresh = False
        
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
        
        self.col_name_width = 300
        self.col_status_width = 140
        self.col_score_width = 110
        self.tree_threats.column("#0", width=self.col_name_width, anchor="w", stretch=False) 
        self.tree_threats.column("Status", width=self.col_status_width, anchor="e", stretch=False)
        self.tree_threats.column("Score", width=self.col_score_width, anchor="e", stretch=False)
        self.tree_threats.bind("<Double-1>", self.on_double_click)
        self.tree_threats.bind("<Button-1>", self.on_left_click) 
        self.tree_threats.bind("<Motion>", self.on_mouse_move)
        self.tree_threats.bind("<Button-3>", self.on_right_click)

        tk.Label(main, text="CLEAN FILES", bg="#202020", fg="#6cc4ff", 
                 font=("Segoe UI Variable Text", 9, "bold")).pack(anchor="w", pady=(15, 5))
        frame_clean = tk.Frame(main, bg="#202020", height=150, highlightthickness=0, borderwidth=0)
        frame_clean.pack(fill=tk.X)
        frame_clean.pack_propagate(False)
        self.tree_clean = ttk.Treeview(frame_clean, columns=("Status", "Score"), show='tree', style="Custom.Treeview")
        self.tree_clean.pack(fill=tk.BOTH, expand=True)
        self.tree_clean.column("#0", width=self.col_name_width, anchor="w", stretch=False)
        self.tree_clean.column("Status", width=self.col_status_width, anchor="e", stretch=False)
        self.tree_clean.column("Score", width=self.col_score_width, anchor="e", stretch=False)
        self.tree_clean.bind("<Double-1>", self.on_double_click)
        self.tree_clean.bind("<Button-1>", self.on_left_click)
        self.tree_clean.bind("<Motion>", self.on_mouse_move)
        self.tree_clean.bind("<Button-3>", self.on_right_click)

        footer = tk.Frame(self.root, bg="#202020", height=30, highlightthickness=0, borderwidth=0)
        footer.pack(fill=tk.X, padx=15, pady=10)
        btn_scan = tk.Button(footer, text="[+] Scan File...", bg="#3A3A3A", fg="white", 
                             relief=tk.FLAT, activebackground="#505050", activeforeground="white",
                             font=("Segoe UI", 9), command=self.manual_scan)
        btn_scan.pack(side=tk.LEFT)
        self.stats_label = tk.Label(footer, text="0 Threats / 0 Scanned", bg="#202020", fg="#888888", 
                                    font=("Segoe UI Variable Text", 9))
        self.stats_label.pack(side=tk.RIGHT)
        self.context_menu = Menu(self.root, tearoff=0, bg="#2d2d2d", fg="white", activebackground="#3d3d3d", borderwidth=0, font=("Segoe UI", 9))
        self.tooltip = ToolTip(self.root)

    def manual_scan(self):
        path = filedialog.askopenfilename()
        if path:
            sid = str(uuid.uuid4())[:8]
            session_log.create_session(sid, os.path.basename(path), path)
            scan_queue.put((1, next(counter), path, sid))

    def setup_tree_style(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.layout("Custom.Treeview.Item", [('Custom.Treeitem.padding', {'sticky': 'nswe', 
            'children': [('Custom.Treeitem.indicator', {'side': 'left', 'sticky': ''}), ('Custom.Treeitem.image', {'side': 'left', 'sticky': ''}), ('Custom.Treeitem.text', {'side': 'left', 'sticky': ''})]})])
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
        try:
            if self.context_menu.winfo_viewable(): return
        except: pass
        self.root.after(100, self.hide)

    def on_mouse_move(self, event):
        tree = event.widget
        item_id = tree.identify_row(event.y)
        col = tree.identify_column(event.x)
        if not item_id:
            self.tooltip.hidetip()
            return
        if col == '#0' and item_id in self.item_fulltext_map:
            full = self.item_fulltext_map[item_id]
            displayed = tree.item(item_id, 'text').strip()
            if displayed.endswith("...") and full not in displayed:
                 self.tooltip.showtip(full, event.x_root, event.y_root)
                 return
        if col == '#1' and item_id in self.item_status_map:
            full_status = self.item_status_map[item_id]
            vals = tree.item(item_id, 'values')
            if vals:
                displayed = vals[0]
                if displayed.endswith("...") and full_status not in displayed:
                    self.tooltip.showtip(full_status, event.x_root, event.y_root)
                    return
        self.tooltip.hidetip()

    def on_left_click(self, event):
        tree = event.widget
        item_id = tree.identify_row(event.y)
        col = tree.identify_column(event.x)
        if not item_id: return

        if col == '#2':
            data = self.item_session_map.get(item_id)
            if data and data.get('score_str') == '[ Analyze ]':
                tree.set(item_id, 'Score', 'Queued...')
                parent_sid = None
                with history_lock:
                    for s in session_log.sessions:
                        if 'children' in s and data in s['children']:
                            parent_sid = s['id']
                            break
                if parent_sid and scan_engine_ref:
                    scan_engine_ref.analyze_child_manually(parent_sid, data['filename'])

    def on_right_click(self, event):
        tree = event.widget
        item_id = tree.identify_row(event.y)
        if not item_id: return
        tree.selection_set(item_id)
        data = self.item_session_map.get(item_id)
        if not data: return
        self.context_menu.delete(0, tk.END)
        fp = data.get('filepath')
        is_container = data.get('is_container', False)
        
        if fp and os.path.exists(fp):
            self.context_menu.add_command(label="Open File Location", command=lambda: self.open_loc(fp))
            
        if not is_container:
            link = data.get('link')
            if link:
                self.context_menu.add_command(label="Open VirusTotal3 Report", command=lambda: webbrowser.open(link))
                self.context_menu.add_command(label="Copy SHA-256", command=lambda: self.copy_sha(link))
        
        self.context_menu.post(event.x_root, event.y_root)

    def open_loc(self, path):
        try: os.startfile(os.path.dirname(path))
        except: pass

    def copy_sha(self, link):
        try:
            sha = link.split('/')[-1]
            pyperclip.copy(sha)
        except: pass

    def on_double_click(self, event):
        tree = event.widget
        try:
            item_id = tree.identify_row(event.y)
            if not item_id: return
            
            tags = tree.item(item_id, 'tags')
            if 'vendor' in tags or 'trusted_vendor' in tags:
                full_text = self.item_fulltext_map.get(item_id, "")
                if full_text: pyperclip.copy(full_text)
                return

            data = self.item_session_map.get(item_id)
            if not data: return
            
            is_container = data.get('is_container', False)
            if is_container:
                if data.get('filepath') and os.path.exists(data['filepath']):
                     self.open_loc(data['filepath'])
            else:
                if data.get('link'):
                     webbrowser.open(data['link'])
        except: pass

    def refresh_safe(self):
        if not self._pending_refresh:
            self._pending_refresh = True
            self.root.after(200, self._do_refresh_throttle)

    def _do_refresh_throttle(self):
        self._pending_refresh = False
        self.refresh()

    def refresh(self):
        for i in self.tree_threats.get_children(): self.tree_threats.delete(i)
        for i in self.tree_clean.get_children(): self.tree_clean.delete(i)
        
        self.item_fulltext_map.clear()
        self.item_status_map.clear()
        self.item_session_map.clear()

        W_NAME_SAFE = self.col_name_width - 35
        W_STATUS_SAFE = self.col_status_width - 15
        W_NAME_CHILD = W_NAME_SAFE - 20 
        W_NAME_GRANDCHILD = W_NAME_CHILD - 20

        with history_lock:
            for s in session_log.sessions:
                score_val = s['score_val']
                status = s['status'] 
                children = s.get('children', [])
                display_name = s['filename']
                
                det_str = status
                if s['detections']:
                    c = collections.Counter([d[1] for d in s['detections']])
                    if c:
                        most_common = c.most_common(1)[0][0]
                        det_str = f"[{most_common}]"
                elif "Scanning" in status: det_str = "Scanning..."
                
                is_container = s.get('is_container', False)
                if is_container:
                    bad_children = [c for c in children if c.get('score_val', 0) > 0]
                    clean_children = [c for c in children if c.get('score_val', 0) == 0]
                    folder_status_str = f"{len(bad_children)}/{len(children)} Infected"

                    if bad_children:
                        tag = 'danger'
                        disp_name = pixel_truncate(display_name, self.font, W_NAME_SAFE)
                        disp_status = pixel_truncate(folder_status_str, self.font, W_STATUS_SAFE)
                        p_node = self.tree_threats.insert("", "end", text=f" {disp_name}", 
                                                          values=(disp_status, ""), open=False, tags=(tag,))
                        self.item_fulltext_map[p_node] = display_name
                        self.item_status_map[p_node] = folder_status_str
                        self.item_session_map[p_node] = s
                        for child in bad_children:
                            c_node = self.add_child_row(self.tree_threats, p_node, child, W_NAME_CHILD, W_STATUS_SAFE)
                            if child.get('detections'):
                                self.add_detections(self.tree_threats, c_node, child['detections'], W_NAME_GRANDCHILD, W_STATUS_SAFE)

                    if clean_children:
                        tag = 'safe' if not bad_children else 'warn'
                        disp_name = pixel_truncate(display_name, self.font, W_NAME_SAFE)
                        disp_status = pixel_truncate(folder_status_str, self.font, W_STATUS_SAFE)
                        p_node = self.tree_clean.insert("", "end", text=f" {disp_name}", 
                                                         values=(disp_status, ""), open=False, tags=(tag,))
                        self.item_fulltext_map[p_node] = display_name
                        self.item_status_map[p_node] = folder_status_str
                        self.item_session_map[p_node] = s
                        for child in clean_children:
                            c_node = self.add_child_row(self.tree_clean, p_node, child, W_NAME_CHILD, W_STATUS_SAFE)
                            if child.get('detections'):
                                self.add_detections(self.tree_clean, c_node, child['detections'], W_NAME_GRANDCHILD, W_STATUS_SAFE)
                else:
                    disp_name = pixel_truncate(display_name, self.font, W_NAME_SAFE)
                    disp_status = pixel_truncate(det_str, self.font, W_STATUS_SAFE)
                    if score_val > 0:
                        tag = 'danger' if score_val >= CONFIRMED_THREAT_THRESHOLD else 'warn'
                        p_node = self.tree_threats.insert("", "end", text=f" {disp_name}", 
                                               values=(disp_status, s['score_str']), open=False, tags=(tag,))
                        self.item_fulltext_map[p_node] = display_name
                        self.item_status_map[p_node] = det_str
                        self.item_session_map[p_node] = s
                        if s['detections']:
                            self.add_detections(self.tree_threats, p_node, s['detections'], W_NAME_CHILD, W_STATUS_SAFE)
                    else:
                        tag = 'wait' if "Scanning" in status else 'safe'
                        p_node = self.tree_clean.insert("", "end", text=f" {disp_name}", 
                                                         values=(disp_status, s['score_str']), tags=(tag,))
                        self.item_fulltext_map[p_node] = display_name
                        self.item_status_map[p_node] = det_str
                        self.item_session_map[p_node] = s

        for tree in [self.tree_threats, self.tree_clean]:
            tree.tag_configure('danger', foreground=self.colors['danger']) 
            tree.tag_configure('warn', foreground=self.colors['warn'])
            tree.tag_configure('safe', foreground=self.colors['safe'])
            tree.tag_configure('wait', foreground=self.colors['wait'])
            tree.tag_configure('vendor', foreground=self.colors['vendor']) 
            tree.tag_configure('trusted_vendor', foreground=self.colors['trusted_vendor']) 
            tree.tag_configure('threat', foreground=self.colors['threat'])
            tree.tag_configure('action', foreground=self.colors['action']) 
        
        t, tot = session_log.get_stats()
        self.stats_label.config(text=f"{t} Threats / {tot} Scanned")

    def add_child_row(self, tree, parent, child, w_name, w_status):
        c_name = child['filename']
        c_status = child.get('status', 'Clean') 
        score_val = child.get('score_val', 0)
        score_str = child.get('score_str', "")
        
        if child.get('detections'):
             c = collections.Counter([d[1] for d in child['detections']])
             if c: c_status = f"[{c.most_common(1)[0][0]}]"
         
        disp_name = pixel_truncate(c_name, self.font, w_name)
        disp_status = pixel_truncate(c_status, self.font, w_status)

        tag = 'safe'
        if score_val >= CONFIRMED_THREAT_THRESHOLD: tag = 'danger'
        elif score_val > 0: tag = 'warn'
        else:
            if "Scanning" in c_status: tag = 'wait'
            elif score_str == "[ Analyze ]": tag = 'action'
            else: tag = 'safe'

        c_node = tree.insert(parent, "end", text=f" {disp_name}", 
                             values=(disp_status, score_str), tags=(tag,))
        self.item_fulltext_map[c_node] = c_name
        self.item_status_map[c_node] = c_status
        self.item_session_map[c_node] = child
        return c_node

    def add_detections(self, tree, parent, detections, w_v, w_t):
        for vendor, threat_name in detections:
            is_trusted = vendor in TRUSTED_VENDORS
            vendor_tag = 'trusted_vendor' if is_trusted else 'vendor'
            disp_vendor = pixel_truncate(vendor, self.font, w_v)
            disp_threat = pixel_truncate(threat_name, self.font, w_t)
            vendor_node = tree.insert(parent, "end", text=f" {disp_vendor}", 
                                      values=(disp_threat, ""), tags=(vendor_tag,))
            self.item_fulltext_map[vendor_node] = f"{vendor}: {threat_name}"
            self.item_status_map[vendor_node] = threat_name

    def run(self):
        self.root.mainloop()

# --- SCAN ENGINE ---
class ScanEngine(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.session = requests.Session()
        global scan_engine_ref
        scan_engine_ref = self
        self.executor = ThreadPoolExecutor(max_workers=5)
        self.start()

    def run(self):
        while True:
            prio, _, filepath, session_id = scan_queue.get()
            try:
                self.executor.submit(self.safe_analyze, filepath, session_id)
            except Exception as e:
                session_log.update_status(session_id, "Error", 0, str(e))
            finally:
                scan_queue.task_done()

    def safe_analyze(self, filepath, session_id):
        try:
            self.analyze(filepath, session_id)
        except Exception as e:
            session_log.update_status(session_id, "Error", 0, str(e)[:25])

    def analyze(self, filepath, session_id):
        if not os.path.exists(filepath): return
        try:
            if os.path.getsize(filepath) > (MAX_FILE_SIZE_MB * 1024 * 1024):
                session_log.update_status(session_id, "Too Large")
                return
        except: pass

        filename = os.path.basename(filepath)
        if not self.wait_for_file(filepath): return
        fhash = self.get_hash(filepath)
        if not fhash: return

        if filename.lower().endswith('.zip') or (os.path.isdir(filepath)):
            if is_zip_encrypted(filepath):
                 session_log.update_status(session_id, "Locked Zip")
                 pwd = get_password_from_console(filename)
            else: pwd = None
            if filename.lower().endswith('.zip'):
                self.handle_zip(filepath, session_id, pwd)
                return

        if HASH_ONLY_MODE:
             report = self.query_vt(fhash)
             if report: self.process(filepath, report, session_id)
             else: session_log.update_status(session_id, "Unknown (Hash Only)")
             return

        report = self.query_vt(fhash)
        if report:
            self.process(filepath, report, session_id)
        else:
            self.upload_flow_safe(filepath, filename, session_id)

    def handle_zip(self, filepath, session_id, pwd):
        try:
            children_results = []
            with tempfile.TemporaryDirectory() as temp_dir:
                with pyzipper.AESZipFile(filepath) as zf:
                    if pwd: zf.extractall(path=temp_dir, pwd=pwd.encode('utf-8'))
                    else: zf.extractall(path=temp_dir)
                for root, dirs, files in os.walk(temp_dir):
                    for file in files:
                        full_p = os.path.join(root, file)
                        if not os.path.abspath(full_p).startswith(os.path.abspath(temp_dir)): continue
            
                        inner_hash = self.get_hash(full_p)
                        child_entry = {
                            "filename": file, "filepath": full_p, "score_val": 0, "score_str": "Clean",
                            "status": "Clean", "detections": [], "link": ""
                        }
                        if inner_hash:
                            rep = self.query_vt(inner_hash)
                            if rep:
                                stats = rep.get('attributes', {}).get('last_analysis_stats', {})
                                mal = stats.get('malicious', 0)
                                tot = sum(stats.values())
                                link = f"https://www.virustotal.com/gui/file/{rep['attributes']['sha256']}"
                                results = rep.get('attributes', {}).get('last_analysis_results', {})
                                det_data = []
                                for vendor, res in results.items():
                                    if res['category'] == 'malicious':
                                        det_data.append((vendor, res['result']))
                                
                                trusted = sorted([d for d in det_data if d[0] in TRUSTED_VENDORS], key=lambda x: x[0])
                                others = sorted([d for d in det_data if d[0] not in TRUSTED_VENDORS], key=lambda x: x[0])
                                final_dets = trusted + others
                                
                                child_entry['score_val'] = mal
                                child_entry['score_str'] = f"{mal}/{tot}"
                                child_entry['detections'] = final_dets
                                child_entry['link'] = link
                                
                                if mal > 0: child_entry['status'] = "Threat"
                            else:
                                child_entry['status'] = "Unknown"
                                child_entry['score_str'] = "[ Analyze ]"

                        children_results.append(child_entry)
            threat_count = sum(1 for c in children_results if c['score_val'] > 0)
            status = "Threats Found" if threat_count > 0 else "Clean"
            session_log.update_status(session_id, status, threat_count, f"{threat_count} Infected", [], "", children_results)
        except Exception as e:
            session_log.update_status(session_id, "Zip Error", 0, str(e)[:20])

    def analyze_child_manually(self, parent_id, child_filename):
        self.executor.submit(self._manual_child_upload_task, parent_id, child_filename)

    def _manual_child_upload_task(self, parent_id, child_filename):
        parent_path = None
        with history_lock:
            for s in session_log.sessions:
                if s['id'] == parent_id:
                    parent_path = s['filepath']
                    for c in s.get('children', []):
                        if c['filename'] == child_filename:
                            c['score_str'] = "Queued..."
                            break
                    break
        
        if not parent_path or not os.path.exists(parent_path): return
        
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                target_path = None
                if os.path.isdir(parent_path):
                     for root, dirs, files in os.walk(parent_path):
                         if child_filename in files:
                             target_path = os.path.join(root, child_filename)
                             break
                else:
                    with pyzipper.AESZipFile(parent_path) as zf:
                        target_info = None
                        for info in zf.infolist():
                            if os.path.basename(info.filename) == child_filename:
                                target_info = info
                                break
                        if target_info:
                            zf.extract(target_info, path=temp_dir)
                            target_path = os.path.join(temp_dir, target_info.filename)
                
                if target_path and os.path.exists(target_path):
                     session_log.update_child_status(parent_id, child_filename, "Uploading...", "...")
                     self.upload_child_flow(target_path, child_filename, parent_id)
                else:
                     session_log.update_child_status(parent_id, child_filename, "Error", "Lost")

        except Exception as e:
            session_log.update_child_status(parent_id, child_filename, "Error", "Fail")

    def upload_child_flow(self, filepath, filename, parent_id):
        try:
            upload_url = "https://www.virustotal.com/api/v3/files"
            file_size_mb = os.path.getsize(filepath) / (1024 * 1024)
            if file_size_mb >= 32:
                r = self.session.get(f"{upload_url}/upload_url", headers={'x-apikey': API_KEY}, timeout=15)
                if r.status_code == 200: upload_url = r.json().get('data')
            
            with open(filepath, 'rb') as f:
                r = self.session.post(upload_url, headers={'x-apikey': API_KEY}, files={'file': (filename, f)}, timeout=300)
            
            if r.status_code == 200:
                analysis_id = r.json()['data']['id']
                session_log.update_child_status(parent_id, filename, "Analyzing...", "...")
                self.poll_child_analysis(analysis_id, filename, parent_id)
            else:
                session_log.update_child_status(parent_id, filename, "Failed", "Err")
        except:
            session_log.update_child_status(parent_id, filename, "Error", "Err")

    def poll_child_analysis(self, analysis_id, filename, parent_id):
        url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        headers = {'x-apikey': API_KEY}
        for _ in range(60): 
            time.sleep(15)
            try:
                r = self.session.get(url, headers=headers, timeout=15)
                if r.status_code == 200:
                    resp_json = r.json()
                    data = resp_json['data']['attributes']
                    if data.get('status') == 'completed':
                        stats = data['stats']
                        mal = stats.get('malicious', 0)
                        tot = sum(stats.values())
                        results = data.get('results', {})
                        sha256 = resp_json.get('meta', {}).get('file_info', {}).get('sha256', '')
                        link = f"https://www.virustotal.com/gui/file/{sha256}"
                        
                        det_data = []
                        for vendor, res in results.items():
                            if res['category'] == 'malicious':
                                det_data.append((vendor, res['result']))
                        
                        with history_lock:
                            for s in session_log.sessions:
                                if s['id'] == parent_id:
                                    for c in s['children']:
                                        if c['filename'] == filename:
                                            c['score_val'] = mal
                                            c['score_str'] = f"{mal}/{tot}"
                                            c['link'] = link
                                            c['detections'] = det_data
                                            c['status'] = "Threat" if mal > 0 else "Clean"
                                    break
                        if gui_app: gui_app.refresh_safe()
                        if mal > 0: send_alert("THREAT FOUND", f"{filename} inside archive is malicious.")
                        return
            except: pass
        session_log.update_child_status(parent_id, filename, "Timeout", "Err")

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
        url = f"https://www.virustotal.com/api/v3/files/{h}"
        headers = {'x-apikey': API_KEY}
        for _ in range(3):
            try:
                r = self.session.get(url, headers=headers, timeout=15)
                if r.status_code == 200: return r.json()['data']
                if r.status_code == 429: 
                    time.sleep(15) 
                    continue
                break
            except: pass
        return None

    def upload_flow_safe(self, filepath, filename, session_id):
        with upload_semaphore:
            self.upload_flow(filepath, filename, session_id)

    def upload_flow(self, filepath, filename, session_id):
        session_log.update_status(session_id, "Uploading...")
        try:
            upload_url = "https://www.virustotal.com/api/v3/files"
            if os.path.getsize(filepath) > (MAX_FILE_SIZE_MB * 1024 * 1024):
                 session_log.update_status(session_id, "Too Large")
                 return

            file_size_mb = os.path.getsize(filepath) / (1024 * 1024)
            if file_size_mb >= 32:
                r = self.session.get(f"{upload_url}/upload_url", headers={'x-apikey': API_KEY}, timeout=15)
                if r.status_code == 200: upload_url = r.json().get('data')
            
            with open(filepath, 'rb') as f:
                r = self.session.post(upload_url, headers={'x-apikey': API_KEY}, files={'file': (filename, f)}, timeout=300)
            
            if r.status_code == 200:
                analysis_id = r.json()['data']['id']
                link = f"https://www.virustotal.com/gui/file-analysis/{analysis_id}"
                session_log.update_status(session_id, "Analyzing...", 0, "", [], link)
                self.poll_analysis(analysis_id, filepath, session_id)
            else:
                session_log.update_status(session_id, "Upload Failed")
        except Exception as e:
            session_log.update_status(session_id, "Error")

    def poll_analysis(self, analysis_id, filepath, session_id):
        url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        headers = {'x-apikey': API_KEY}
        for _ in range(60): 
            time.sleep(15)
            try:
                r = self.session.get(url, headers=headers, timeout=15)
                if r.status_code == 200:
                    resp_json = r.json()
                    data = resp_json['data']['attributes']
                    if data.get('status') == 'completed':
                        sha256 = resp_json.get('meta', {}).get('file_info', {}).get('sha256', 'unknown')
                        fake_report = {
                            'attributes': {
                                'last_analysis_stats': data['stats'],
                                'last_analysis_results': data['results'],
                                'sha256': sha256
                            }
                        }
                        self.process(filepath, fake_report, session_id)
                        return
            except: pass
        session_log.update_status(session_id, "Timed Out")

    def get_hash(self, path):
        h = hashlib.sha256()
        try:
            with open(path, 'rb') as f:
                while True:
                    chunk = f.read(8192) 
                    if not chunk: break
                    h.update(chunk)
            return h.hexdigest()
        except: return None

    def wait_for_file(self, path):
        for _ in range(60):
            try:
                with open(path, 'ab'): pass
                return True
            except: time.sleep(0.5)
        return False

# --- WATCHDOG ---
def run_tray():
    global tray_icon
    def toggle(icon, item):
        if gui_app: gui_app.root.after(0, gui_app.show)
    def exit_app(icon, item): icon.stop(); os._exit(0)
    def toggle_hash_only(icon, item):
        global HASH_ONLY_MODE
        HASH_ONLY_MODE = not HASH_ONLY_MODE
    def toggle_startup(icon, item):
        set_startup(not check_startup())

    menu = (
        item('Show Monitor', toggle, default=True),
        item('Hash-Only Mode', toggle_hash_only, checked=lambda i: HASH_ONLY_MODE),
        item('Run on Startup', toggle_startup, checked=lambda i: check_startup()),
        item('Exit', exit_app)
    )
    tray_icon = pystray.Icon("VT3", create_tray_icon(), "VT3_Monitor_Win11", menu)
    tray_icon.run()

class TrayWatcher(FileSystemEventHandler):
    def __init__(self):
        self.processed = collections.deque(maxlen=50)
    
    def on_created(self, event): self.p(event)
    def on_moved(self, event): 
        if not event.is_directory: self.q(event.dest_path)
    def p(self, event):
        if not event.is_directory: self.q(event.src_path)
    def q(self, fp):
        try:
            fn = os.path.basename(fp)
            if fn.endswith(('.crdownload', '.tmp', '.lock')): return
            
            current_time = time.time()
            for p_path, p_time in self.processed:
                if p_path == fp and (current_time - p_time) < 2.0:
                    return
            self.processed.append((fp, current_time))

            sid = str(uuid.uuid4())[:8]
            session_log.create_session(sid, fn, fp)
            scan_queue.put((3, next(counter), fp, sid))
        except: pass

if __name__ == "__main__":
    load_or_setup_api_key()
    ScanEngine()
    observer = Observer()
    if os.path.exists(DOWNLOADS_PATH):
        observer.schedule(TrayWatcher(), DOWNLOADS_PATH, recursive=False)
    observer.start()
    send_alert("Active", "Monitor Mode")
    threading.Thread(target=run_tray, daemon=True).start()
    app = NativeDashboard()
    app.run()
