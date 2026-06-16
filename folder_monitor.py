import os
import time
import threading
from queue import Queue
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

import forensic_pipeline
import db_manager

class MonitorHandler(FileSystemEventHandler):
    def __init__(self, monitor_instance):
        self.monitor = monitor_instance

    def on_created(self, event):
        if event.is_directory:
            dir_path = os.path.abspath(event.src_path)
            self.monitor.log_event(f"[DETECTED] New folder found: {os.path.basename(dir_path)}. Scanning contents recursively...")
            # Small delay to let the OS write the first files
            time.sleep(0.5)
            try:
                for root, _, files in os.walk(dir_path):
                    for file in files:
                        file_path = os.path.abspath(os.path.join(root, file))
                        self.monitor.enqueue_file(file_path)
            except Exception as e:
                self.monitor.log_event(f"[ERROR] Failed to walk folder {os.path.basename(dir_path)}: {str(e)}")
            return
            
        file_path = os.path.abspath(event.src_path)
        self.monitor.log_event(f"[DETECTED] New file found: {os.path.basename(file_path)}")
        self.monitor.enqueue_file(file_path)

class FolderMonitor:
    def __init__(self):
        self.observer = None
        self.watch_path = None
        self.is_running = False
        self.event_logs = []
        self.log_lock = threading.Lock()
        self.file_queue = Queue()
        self.worker_thread = None
        self.stop_worker_event = threading.Event()

    def log_event(self, message):
        """Append log message with timestamp."""
        timestamp = time.strftime('%H:%M:%S')
        log_entry = f"[{timestamp}] {message}"
        print(log_entry)
        with self.log_lock:
            self.event_logs.append(log_entry)
            # Keep only the last 100 logs
            if len(self.event_logs) > 100:
                self.event_logs.pop(0)

    def get_logs(self):
        with self.log_lock:
            return list(self.event_logs)

    def enqueue_file(self, file_path):
        self.file_queue.put(file_path)

    def _worker(self):
        """Processes files from the queue."""
        self.log_event("Analysis worker thread started.")
        while not self.stop_worker_event.is_set():
            try:
                # Wait for file with 1s timeout to check stop event periodically
                file_path = self.file_queue.get(timeout=1.0)
            except Exception:
                continue

            # Give a very short delay to let the OS release file handles (e.g. copying complete)
            time.sleep(1.0)
            
            # Double check if file exists
            if not os.path.exists(file_path):
                self.log_event(f"[WARN] File no longer exists: {os.path.basename(file_path)}")
                self.file_queue.task_done()
                continue
                
            self.log_event(f"[ANALYZING] Commencing multi-layer analysis on: {os.path.basename(file_path)}")
            try:
                result = forensic_pipeline.run_analysis_pipeline(file_path)
                if result:
                    self.log_event(
                        f"[COMPLETED] {result['filename']} | Score: {result['threat_score']} ({result['risk_level']}) | ML: {result['ml_prediction']}"
                    )
                else:
                    self.log_event(f"[ERROR] Analysis failed for file: {os.path.basename(file_path)}")
            except Exception as e:
                self.log_event(f"[ERROR] Pipeline exception on {os.path.basename(file_path)}: {str(e)}")
            
            self.file_queue.task_done()
            
        self.log_event("Analysis worker thread shut down.")

    def start(self, path):
        if self.is_running:
            self.log_event(f"Monitor is already running on: {self.watch_path}")
            return False, f"Already monitoring {self.watch_path}"
            
        if not os.path.exists(path) or not os.path.isdir(path):
            self.log_event(f"[ERROR] Failed to start: Path does not exist or is not a folder: {path}")
            return False, "Target path does not exist or is not a directory."
            
        self.watch_path = os.path.abspath(path)
        self.log_event(f"[SYSTEM] Starting real-time monitor on: {self.watch_path}")
        
        # Start queue worker
        self.stop_worker_event.clear()
        self.worker_thread = threading.Thread(target=self._worker, daemon=True)
        self.worker_thread.start()

        # Start watchdog observer
        event_handler = MonitorHandler(self)
        self.observer = Observer()
        self.observer.schedule(event_handler, self.watch_path, recursive=False)
        
        try:
            self.observer.start()
            self.is_running = True
            db_manager.add_monitored_path(self.watch_path)
            self.log_event(f"[ACTIVE] Watching for new files...")
            return True, "Folder monitoring started."
        except Exception as e:
            self.is_running = False
            self.stop_worker_event.set()
            self.log_event(f"[ERROR] Watchdog start failed: {str(e)}")
            return False, f"Failed to start filesystem observer: {str(e)}"

    def stop(self):
        if not self.is_running:
            return False, "Monitor is not active."
            
        self.log_event("[SYSTEM] Stopping folder monitor daemon...")
        
        # Stop watchdog observer
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.observer = None
            
        # Stop queue worker
        self.stop_worker_event.set()
        if self.worker_thread:
            self.worker_thread.join(timeout=2.0)
            self.worker_thread = None
            
        self.is_running = False
        db_manager.remove_monitored_path(self.watch_path)
        self.log_event(f"[INACTIVE] Monitoring stopped for path: {self.watch_path}")
        self.watch_path = None
        return True, "Folder monitoring stopped."

    def get_status(self):
        return {
            'is_running': self.is_running,
            'watch_path': self.watch_path,
            'queue_size': self.file_queue.qsize()
        }

# Global singleton monitor instance
monitor_daemon = FolderMonitor()
