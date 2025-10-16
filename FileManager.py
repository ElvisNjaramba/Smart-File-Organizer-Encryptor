import os
import sys
import time
import json
import shutil
import hashlib
import threading
import base64
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, scrolledtext
import winreg

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import pystray
from PIL import Image, ImageDraw
from cryptography.fernet import Fernet

APP_DIR = os.path.join(os.path.expanduser("~"), "AppData", "Roaming", "SmartFileOrganizer")
os.makedirs(APP_DIR, exist_ok=True)
CONFIG_FILE = os.path.join(APP_DIR, "settings.json")

def load_settings():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                return json.load(f)
        except:
            pass
    return {
        "monitor_folder": os.path.join(os.path.expanduser("~"), "Downloads"),
        "run_on_startup": False,
        "cleanup_duplicates": True,
        "monitor_enabled": True,
        "monitor_delay_seconds": 600  
    }

def save_settings(s):
    with open(CONFIG_FILE, "w") as f:
        json.dump(s, f, indent=2)

settings = load_settings()

root = None
log_box = None
observer = None
tray_icon = None
handler = None

HOME = os.path.expanduser("~")
DESTINATIONS = {
    "Videos": os.path.join(HOME, "Videos"),
    "Music": os.path.join(HOME, "Music"),
    "Documents": os.path.join(HOME, "Documents"),
    "Images": os.path.join(HOME, "Pictures"),
    "Desktop": os.path.join(HOME, "Desktop")
}

FILE_TYPES = {
    "Images": [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp"],
    "Videos": [".mp4", ".avi", ".mov", ".mkv", ".flv", ".wmv"],
    "Music": [".mp3", ".wav", ".aac", ".flac", ".ogg"],
    "Documents": [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".odt"],
    "Archives": [".zip", ".rar", ".7z", ".tar", ".gz"],
    "Programs": [".exe", ".msi", ".bat", ".ps1"],
}

def log_message(msg):
    print(msg)
    if log_box and root:
        def append():
            try:
                log_box.insert(tk.END, msg + "\n")
                log_box.see(tk.END)
            except:
                pass
        try:
            root.after(0, append)
        except Exception:
            pass

def get_file_hash(path, chunk_size=8192):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        log_message(f"⚠️ Hash error {path}: {e}")
        return None

def remove_duplicates(folder_path):
    log_message(f"🔎 Checking duplicates in {folder_path} ...")
    seen = {}
    deleted = []
    for root_dir, _, files in os.walk(folder_path):
        for name in files:
            p = os.path.join(root_dir, name)
            if not os.path.isfile(p):
                continue
            file_hash = get_file_hash(p)
            if file_hash is None:
                continue
            if file_hash in seen:
                try:
                    os.remove(p)
                    deleted.append(p)
                    log_message(f"🗑️ Deleted duplicate: {p}")
                except Exception as e:
                    log_message(f"⚠️ Could not delete duplicate {p}: {e}")
            else:
                seen[file_hash] = p
    log_message(f"🔎 Duplicate check done. Deleted: {len(deleted)}")
    return deleted

def classify_category(ext):
    ext = ext.lower()
    for cat, exts in FILE_TYPES.items():
        if ext in exts:
            return cat
    return "Others"

def get_destination_for_extension(ext):
    cat = classify_category(ext)
    if cat == "Videos":
        return DESTINATIONS["Videos"]
    if cat == "Music":
        return DESTINATIONS["Music"]
    if cat == "Documents":
        return DESTINATIONS["Documents"]
    if cat == "Images":
        return DESTINATIONS["Images"]
    return os.path.join(DESTINATIONS["Desktop"], cat)

def organize_item(path):
    try:
        if os.path.isfile(path):
            name = os.path.basename(path)
            _, ext = os.path.splitext(name)
            ext = ext.lower()
            dest_dir = get_destination_for_extension(ext)
            os.makedirs(dest_dir, exist_ok=True)
            target = os.path.join(dest_dir, name)
            if os.path.exists(target):
                base, extension = os.path.splitext(name)
                i = 1
                while os.path.exists(os.path.join(dest_dir, f"{base} ({i}){extension}")):
                    i += 1
                target = os.path.join(dest_dir, f"{base} ({i}){extension}")
            shutil.move(path, target)
            log_message(f"✅ Moved file: {name} -> {dest_dir}")
        elif os.path.isdir(path):
            dest_root = os.path.join(DESTINATIONS["Desktop"], "Folders")
            os.makedirs(dest_root, exist_ok=True)
            name = os.path.basename(path)
            target = os.path.join(dest_root, name)
            if os.path.exists(target):
                i = 1
                while os.path.exists(os.path.join(dest_root, f"{name} ({i})")):
                    i += 1
                target = os.path.join(dest_root, f"{name} ({i})")
            shutil.move(path, target)
            log_message(f"📂 Moved folder: {name} -> {dest_root}")
    except Exception as e:
        log_message(f"⚠️ Error organizing {path}: {e}")

def move_files_in_folder(folder_path):
    if not os.path.exists(folder_path):
        log_message(f"⚠️ Folder does not exist: {folder_path}")
        return
    for item in os.listdir(folder_path):
        file_path = os.path.join(folder_path, item)
        organize_item(file_path)

class DelayedHandler(FileSystemEventHandler):
    def __init__(self):
        super().__init__()
        self.pending = {}

    def on_created(self, event):
        src = event.src_path
        if src in self.pending:
            return
        delay = settings.get("monitor_delay_seconds", 600)
        log_message(f"➕ Detected new item: {src} (will process after {delay} seconds)")
        def delayed():
            time.sleep(delay)
            if os.path.exists(src):
                folder_to_check = settings.get("monitor_folder")
                if settings.get("cleanup_duplicates", True) and os.path.isdir(folder_to_check):
                    try:
                        remove_duplicates(folder_to_check)
                    except Exception as e:
                        log_message(f"⚠️ Duplicate cleanup failed: {e}")
                organize_item(src)
            try:
                del self.pending[src]
            except KeyError:
                pass
        t = threading.Thread(target=delayed, daemon=True)
        self.pending[src] = t
        t.start()

def start_monitor():
    global observer, handler
    if observer:
        log_message("⚠️ Monitor already running.")
        return
    path = settings.get("monitor_folder", os.path.join(HOME, "Downloads"))
    if not os.path.exists(path):
        log_message(f"⚠️ Monitor path does not exist: {path}")
        return
    handler = DelayedHandler()
    observer = Observer()
    observer.schedule(handler, path, recursive=False)
    observer.start()
    log_message(f"▶️ Monitoring started on: {path}")
    settings["monitor_enabled"] = True
    save_settings(settings)

def stop_monitor():
    global observer
    if observer:
        observer.stop()
        observer.join(timeout=2)
        observer = None
        log_message("⏸️ Monitoring stopped.")
    settings["monitor_enabled"] = False
    save_settings(settings)

def set_run_on_startup(enabled):
    app_name = "SmartFileOrganizer"
    exe_path = sys.executable
    try:
        key = winreg.HKEY_CURRENT_USER
        reg_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        with winreg.OpenKey(key, reg_path, 0, winreg.KEY_SET_VALUE) as regkey:
            if enabled:
                winreg.SetValueEx(regkey, app_name, 0, winreg.REG_SZ, exe_path)
                log_message("🔄 Enabled Run on Startup")
            else:
                try:
                    winreg.DeleteValue(regkey, app_name)
                    log_message("🚫 Disabled Run on Startup")
                except FileNotFoundError:
                    pass
    except Exception as e:
        log_message(f"⚠️ Could not update startup registry: {e}")

def password_to_key(password: str) -> bytes:
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)

def encrypt_file_with_password(file_path, password):
    try:
        key = password_to_key(password)
        f = Fernet(key)
        with open(file_path, "rb") as fh:
            data = fh.read()
        enc = f.encrypt(data)
        new_path = file_path + ".locked"
        with open(new_path, "wb") as fh:
            fh.write(enc)
        os.remove(file_path)
        log_message(f"🔒 Encrypted: {file_path} -> {new_path}")
    except Exception as e:
        log_message(f"❌ Encryption failed for {file_path}: {e}")

def decrypt_file_with_password(file_path, password):
    try:
        key = password_to_key(password)
        f = Fernet(key)
        with open(file_path, "rb") as fh:
            data = fh.read()
        dec = f.decrypt(data)
        orig_path = file_path
        if orig_path.endswith(".locked"):
            orig_path = orig_path[:-7]
        with open(orig_path, "wb") as fh:
            fh.write(dec)
        os.remove(file_path)
        log_message(f"🔓 Decrypted: {file_path} -> {orig_path}")
    except Exception as e:
        log_message(f"❌ Decryption failed for {file_path}: {e}")

def encrypt_folder_recursive(folder_path, password):
    count = 0
    for root_dir, _, files in os.walk(folder_path):
        for name in files:
            p = os.path.join(root_dir, name)
            if p.endswith(".locked"):
                continue
            encrypt_file_with_password(p, password)
            count += 1
    log_message(f"🔐 Encrypted {count} files in folder {folder_path}")

def decrypt_folder_recursive(folder_path, password):
    count = 0
    for root_dir, _, files in os.walk(folder_path):
        for name in files:
            p = os.path.join(root_dir, name)
            if not p.endswith(".locked"):
                continue
            decrypt_file_with_password(p, password)
            count += 1
    log_message(f"🔓 Decrypted {count} files in folder {folder_path}")

def ui_encrypt_file():
    p = filedialog.askopenfilename(title="Select file to encrypt")
    if not p:
        return
    if not messagebox.askyesno("Confirm", f"Encrypt this file?\n{p}"):
        return
    pwd = simpledialog.askstring("Password", "Enter encryption password:", show="*")
    if not pwd:
        log_message("⚠️ Encryption canceled (no password).")
        return
    encrypt_file_with_password(p, pwd)

def ui_decrypt_file():
    p = filedialog.askopenfilename(title="Select .locked file to decrypt", filetypes=[("Locked files", "*.locked"), ("All files", "*.*")])
    if not p:
        return
    if not messagebox.askyesno("Confirm", f"Decrypt this file?\n{p}"):
        return
    pwd = simpledialog.askstring("Password", "Enter decryption password:", show="*")
    if not pwd:
        log_message("⚠️ Decryption canceled (no password).")
        return
    decrypt_file_with_password(p, pwd)

def ui_encrypt_folder():
    p = filedialog.askdirectory(title="Select folder to encrypt")
    if not p:
        return
    if not messagebox.askyesno("Confirm", f"Encrypt ALL files in:\n{p} ?"):
        return
    pwd = simpledialog.askstring("Password", "Enter encryption password:", show="*")
    if not pwd:
        log_message("⚠️ Encryption canceled (no password).")
        return
    threading.Thread(target=encrypt_folder_recursive, args=(p, pwd), daemon=True).start()

def ui_decrypt_folder():
    p = filedialog.askdirectory(title="Select folder to decrypt")
    if not p:
        return
    if not messagebox.askyesno("Confirm", f"Decrypt ALL .locked files in:\n{p} ?"):
        return
    pwd = simpledialog.askstring("Password", "Enter decryption password:", show="*")
    if not pwd:
        log_message("⚠️ Decryption canceled (no password).")
        return
    threading.Thread(target=decrypt_folder_recursive, args=(p, pwd), daemon=True).start()

def create_tray_image():
    img = Image.new("RGBA", (64, 64), (255, 255, 255, 0))
    d = ImageDraw.Draw(img)
    d.ellipse((8, 8, 56, 56), fill=(30, 120, 220, 255))
    return img

def tray_show_ui(icon, item):
    if root:
        try:
            root.after(0, lambda: root.deiconify())
        except:
            pass

def tray_exit(icon, item):
    log_message("⏹️ Exiting (tray requested).")
    try:
        if observer:
            observer.stop()
            observer.join(timeout=2)
    except:
        pass
    try:
        icon.stop()
    except:
        pass
    os._exit(0)

def start_tray():
    global tray_icon
    tray_icon = pystray.Icon("SmartOrganizer", create_tray_image(), "Smart File Organizer",
                             menu=pystray.Menu(
                                 pystray.MenuItem("Show UI", tray_show_ui),
                                 pystray.MenuItem("Exit", tray_exit)
                             ))
    tray_icon.run()

def perform_manual_move(delay_seconds=0):
    folder = settings.get("monitor_folder")
    if not folder or not os.path.exists(folder):
        log_message("⚠️ No valid monitored folder selected.")
        return
    def worker():
        if delay_seconds > 0:
            log_message(f"⏳ Waiting {delay_seconds} seconds before moving files from {folder} ...")
            time.sleep(delay_seconds)
        if settings.get("cleanup_duplicates", True):
            try:
                remove_duplicates(folder)
            except Exception as e:
                log_message(f"⚠️ Duplicate cleanup failed: {e}")
        move_files_in_folder(folder)
        log_message("✅ Move completed.")
    threading.Thread(target=worker, daemon=True).start()

def move_now_custom():
    mins = simpledialog.askinteger("Custom Move", "Enter minutes to wait before moving (0 = now):", minvalue=0)
    if mins is None:
        return
    perform_manual_move(delay_seconds=mins * 60)

def choose_monitor_folder():
    p = filedialog.askdirectory(title="Choose folder to monitor")
    if not p:
        return
    settings["monitor_folder"] = p
    save_settings(settings)
    log_message(f"📂 Monitoring folder set to: {p}")
    if settings.get("monitor_enabled", True):
        stop_monitor()
        time.sleep(0.2)
        start_monitor()

def toggle_startup_button():
    settings["run_on_startup"] = not settings.get("run_on_startup", False)
    save_settings(settings)
    set_run_on_startup(settings["run_on_startup"])
    startup_btn.config(text=f"Run on Startup: {'ON' if settings['run_on_startup'] else 'OFF'}")

def toggle_duplicates():
    settings["cleanup_duplicates"] = dup_var.get()
    save_settings(settings)
    log_message(f"⚙️ Duplicate cleanup set to: {settings['cleanup_duplicates']}")

def toggle_monitor():
    if settings.get("monitor_enabled", True):
        stop_monitor()
        btn_monitor.config(text="Start Monitor")
    else:
        start_monitor()
        btn_monitor.config(text="Stop Monitor")

def on_close_window():
    if messagebox.askyesno("Hide", "Close window to tray? (monitor will continue running)"):
        root.withdraw()
        log_message("🛠️ UI hidden (in tray), monitor still running.")

def quit_app():
    if not messagebox.askyesno("Exit", "Stop monitor and exit the application?"):
        return
    try:
        if observer:
            observer.stop()
            observer.join(timeout=2)
    except:
        pass
    try:
        if tray_icon:
            tray_icon.stop()
    except:
        pass
    log_message("⏹️ Application fully exited.")
    root.destroy()
    os._exit(0)

def set_monitor_delay_custom():
    mins = simpledialog.askinteger("Custom Delay", "Enter delay in minutes:", minvalue=0)
    if mins is None:
        return
    seconds = int(mins) * 60
    settings["monitor_delay_seconds"] = seconds
    save_settings(settings)
    delay_label.config(text=f"Monitor delay: {mins} min")
    log_message(f"⏱️ Monitor delay set to {mins} minutes.")

def build_ui():
    global root, log_box, startup_btn, dup_var, btn_monitor, delay_label, move_mode_var
    root = tk.Tk()
    root.title("Smart File Organizer & Encryptor")
    root.geometry("800x700")

    top = tk.Frame(root)
    top.pack(fill="x", padx=8, pady=8)

    tk.Button(top, text="Choose Folder to Monitor", command=choose_monitor_folder).pack(side="left", padx=4)
    btn_monitor = tk.Button(top, text="Stop Monitor" if settings.get("monitor_enabled") else "Start Monitor", command=toggle_monitor)
    btn_monitor.pack(side="left", padx=4)
    startup_btn = tk.Button(top, text=f"Run on Startup: {'ON' if settings.get('run_on_startup') else 'OFF'}", command=toggle_startup_button)
    startup_btn.pack(side="left", padx=4)

    dup_var = tk.BooleanVar(value=settings.get("cleanup_duplicates", True))
    tk.Checkbutton(top, text="Remove duplicates", variable=dup_var, command=toggle_duplicates).pack(side="left", padx=4)

    delay_label = tk.Label(top, text=f"Monitor delay: {settings.get('monitor_delay_seconds', 600)//60} min")
    delay_label.pack(side="left", padx=4)
    tk.Button(top, text="Set Delay", command=set_monitor_delay_custom).pack(side="left", padx=4)

    timing_frame = tk.Frame(root)
    timing_frame.pack(fill="x", padx=8, pady=8)
    tk.Button(timing_frame, text="Move Now (Custom Minutes)", command=move_now_custom).pack(side="left", padx=6)

    encrypt_frame = tk.LabelFrame(root, text="Encryption / Decryption", padx=4, pady=4)
    encrypt_frame.pack(fill="x", padx=8, pady=4)

    tk.Button(encrypt_frame, text="Encrypt File", command=ui_encrypt_file).pack(side="left", padx=4)
    tk.Button(encrypt_frame, text="Decrypt File", command=ui_decrypt_file).pack(side="left", padx=4)
    tk.Button(encrypt_frame, text="Encrypt Folder", command=ui_encrypt_folder).pack(side="left", padx=4)
    tk.Button(encrypt_frame, text="Decrypt Folder", command=ui_decrypt_folder).pack(side="left", padx=4)

    bottom = tk.Frame(root)
    bottom.pack(fill="x", padx=8, pady=8)
    tk.Button(bottom, text="Quit App", command=quit_app).pack(side="right", padx=6)

    log_box = scrolledtext.ScrolledText(root, height=25)
    log_box.pack(fill="both", expand=True, padx=8, pady=8)

    root.protocol("WM_DELETE_WINDOW", on_close_window)

if __name__ == "__main__":
    build_ui()
    if settings.get("monitor_enabled", True):
        start_monitor()
    threading.Thread(target=start_tray, daemon=True).start()
    root.mainloop()
