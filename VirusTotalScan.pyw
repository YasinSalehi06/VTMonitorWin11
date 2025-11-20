import os
import time
import hashlib
import requests
import webbrowser
import sys
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from plyer import notification 

API_KEY = "bf005c5c7c9af4b21a7b85e4bec957e0955255300e7dc3aa9cb46b9755543b06" 
DOWNLOADS_PATH = os.path.expanduser('~/Downloads')
MAX_FILE_SIZE_MB = 32 
ARCHIVE_EXTENSIONS = ('.zip', '.rar', '.7z', '.tar', '.gz', '.iso', '.7zip') 

def send_windows_notification(title, message, timeout=1):
    notification.notify(
        title=title,
        message=message,
        app_name='VirusTotal', 
        timeout=timeout,
    )

class VirusTotalHandler(FileSystemEventHandler):
    
    def on_created(self, event):
        self.process_file_event(event.src_path, event.is_directory)

    def on_moved(self, event):
        self.process_file_event(event.dest_path, event.is_directory)

    def process_file_event(self, filepath, is_directory):
        if is_directory or filepath.endswith(('.tmp', '.crdownload', '.part', '.ini', '.download', '.temp', '.DS_Store')):
            return

        if not self.wait_for_file(filepath):
            return

        if filepath.lower().endswith(ARCHIVE_EXTENSIONS):
            webbrowser.open("https://www.virustotal.com/gui/home/upload")
            
            send_windows_notification(
                title="Manual Action Required",
                message=f"{os.path.basename(filepath)}"
            )
        else:
            self.scan_file(filepath)
        
    def wait_for_file(self, filepath):
        historical_size = -1
        wait_counter = 0
        while wait_counter < 20: 
            try:
                current_size = os.path.getsize(filepath)
                if current_size == historical_size and current_size > 0:
                    return True
                historical_size = current_size
                time.sleep(0.01)
                wait_counter += 1
            except FileNotFoundError:
                return False
        return True

    def scan_file(self, filepath):
        filename = os.path.basename(filepath)
        try:
            if os.path.getsize(filepath) / (1024 * 1024) > MAX_FILE_SIZE_MB:
                send_windows_notification("Scan Skipped", f"File: {filename}. Exceeds {MAX_FILE_SIZE_MB}MB limit.", timeout=2)
                return

            sha256_hash = hashlib.sha256()
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(65536), b""): 
                    sha256_hash.update(byte_block)
            file_hash = sha256_hash.hexdigest()

            files = {'file': (filename, open(filepath, 'rb'))}
            headers = {'x-apikey': API_KEY}
            response = requests.post('https://www.virustotal.com/api/v3/files', headers=headers, files=files)
            
            if response.status_code == 200 or response.status_code == 409:
                webbrowser.open(f"https://www.virustotal.com/gui/file/{file_hash}")
                
                send_windows_notification(
                    title="Scan Initiated",
                    message=f"{os.path.basename(filepath)}"
                )
            
            elif response.status_code in [401, 403]:
                send_windows_notification("Authentication Error", f"API key invalid or limit reached. File: {filename}.", timeout=2)
            else:
                 send_windows_notification("Submission Failed", f"Error for {filename}. Status: {response.status_code}", timeout=2)

        except Exception as e:
            send_windows_notification("Critical Error", f"Process fail: {filename}.", timeout=2)

if __name__ == "__main__":

    observer = Observer()
    event_handler = VirusTotalHandler()
    observer.schedule(event_handler, DOWNLOADS_PATH, recursive=False)
    observer.start()
    
    send_windows_notification(
        title="VirusTotal",
        message="Monitoring downloads"
    )

    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        observer.stop()
    finally:
        observer.join()
        sys.exit(0)
