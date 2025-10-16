## Smart File Organizer & Encryptor

One-file Windows utility that watches a folder (default: Downloads), automatically organizes new files into destination folders (Images, Videos, Music, Documents, Desktop → categorized subfolders), optionally deduplicates by SHA-256, and provides simple file/folder encryption (Fernet, password→key). Includes a Tkinter UI and a system tray icon.

## Features

1. Watch a folder (default ~/Downloads) with watchdog and process newly created items     after a configurable delay.

2. Classify files by extension into categories: Images, Videos, Music, Documents, Archives, Programs, Others.

3. Move files into user destinations (Pictures, Videos, Music, Documents, Desktop). Directories move into Desktop/Folders.

4. Duplicate detection (SHA-256) with optional automatic deletion of duplicate files in the monitored folder.

5. Encrypt/decrypt single files or whole folders recursively using Fernet (password → sha256 → key → URL-safe base64).

6. Simple Tkinter GUI for controls (choose folder, start/stop monitor, toggle duplicate cleanup, set monitor delay).

7. System tray icon (via pystray) to hide UI while monitor runs.

8. Manual "Move Now" (immediate run) with optional delay input.

9. Windows startup toggle (adds/removes entry under HKCU\...\Run) for convenience.

# Important warnings

> This script manipulates and moves/deletes files. Back up important data before using.

> Encryption is password-dependent: losing the password means losing access to encrypted data. There is no recovery/backdoor.

> The "remove duplicates" feature deletes files it deems duplicates. Use cautiously (consider dry runs).

> Designed and tested for Windows (uses winreg, default paths like AppData\Roaming). It may run partially on other OSes but startup registry and tray behavior are Windows-centric.

# Requirements 

Python 3.8+ (3.10+ recommended)

Windows OS recommended for full functionality

Python packages:

# pip install watchdog cryptography pystray pillow

Optional (if packaging with PyInstaller):

# pip install pyinstaller


# Install & run

Clone or copy the script to your machine:

# git clone https://github.com/ElvisNjaramba/Smart-File-Organizer-Encrypt
# cd Smart-File-Organizer-Encrypt


Create a virtual environment (recommended) and install dependencies:

# python -m venv venv
# venv\Scripts\activate
# pip install -r requirements.txt

Run:

# python FileManager.py


The GUI will appear. The tray icon will start and the monitor will run if enabled in settings.

# Usage

Choose Folder to Monitor — set which folder the app watches for new files.

Start/Stop Monitor — toggle the automatic watcher.

Run on Startup — toggles a HKCU registry value to launch the current Python interpreter at login (useful if you package into an .exe).

Remove duplicates — checkbox to enable/disable dedupe when running a move.

Set Delay — configure how long (minutes) the app waits after a file is created before organizing it.

Move Now (Custom Minutes) — trigger a manual organization run with an optional wait time.

Encrypt File / Decrypt File — dialog opens to pick a file, then prompt for a password; results are .locked files for encrypted output.

Encrypt Folder / Decrypt Folder — recursively encrypt/decrypt files in a chosen directory. Long operations run on background threads.

Quit App — stops monitor and exits.

# Configuration & defaults

Settings are stored in:

%APPDATA%\SmartFileOrganizer\settings.json

# How it works (technical overview)

1. Monitoring: watchdog Observer is scheduled on the configured folder. When a created event fires, the script schedules a delayed worker thread (delay = monitor_delay_seconds) before processing to avoid half-written files.

2. Organizing: Based on file extension categories, files are moved into corresponding destination directories. Name collisions create a (n) suffix.

3. Duplicates: Uses hashlib.sha256 to fingerprint files and remove exact-content duplicates found under a folder walk.

4. Encryption: Password → SHA-256 digest → base64 URLsafe → feed into cryptography.Fernet. Files are replaced by a .locked file containing the encrypted bytes.

5. Tray/UI: pystray creates tray menu; tkinter is used for UI dialogs and a scrolledtext log window.

6. Startup: Uses winreg to add/remove the current Python executable in HKCU\Software\Microsoft\Windows\CurrentVersion\Run.





# Packaging (optional)

To create a single-file executable (for distribution to non-Python users), use PyInstaller:

# pip install pyinstaller
# pyinstaller --onefile --noconsole organizer_encryptor.py


# Notes:

The script relies on pystray + pillow for the icon; PyInstaller may need --hidden-import entries for some platform backends.

winreg startup behavior uses the packaged executable path; test the startup toggle after packaging.

