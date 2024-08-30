import os
import time
import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


VIRUSTOTAL_API_KEY = '54f738b81a18594d278037ff0b281210c5ea94550cc1f543e038e43c96daa04d'


WATCH_DIRECTORY = '/app/watch'
RESULTS_DIRECTORY = '/app/results'


def scan_file(file_path):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    files = {'file': (os.path.basename(file_path), open(file_path, 'rb'))}
    params = {'apikey': VIRUSTOTAL_API_KEY}
    response = requests.post(url, files=files, params=params)
    return response.json()


def save_results(file_name, results):
    result_file_path = os.path.join(RESULTS_DIRECTORY, f"{file_name}_results.txt")
    with open(result_file_path, 'w') as f:
        f.write(str(results))
    print(f"Results saved to {result_file_path}")


class FileHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            print(f"New file detected: {event.src_path}")

            results = scan_file(event.src_path)

            save_results(os.path.basename(event.src_path), results)

class Watcher:
    def __init__(self, directory_to_watch):
        self.observer = Observer()
        self.directory_to_watch = directory_to_watch

    def run(self):
        event_handler = FileHandler()
        self.observer.schedule(event_handler, self.directory_to_watch, recursive=True)
        self.observer.start()
        try:
            while True:
                time.sleep(5)
        except KeyboardInterrupt:
            self.observer.stop()
            print("Observer Stopped")

        self.observer.join()

if __name__ == "__main__":
    if not os.path.exists(WATCH_DIRECTORY):
        os.makedirs(WATCH_DIRECTORY)
    if not os.path.exists(RESULTS_DIRECTORY):
        os.makedirs(RESULTS_DIRECTORY)

    print(f"Watching directory: {WATCH_DIRECTORY}")
    watcher = Watcher(WATCH_DIRECTORY)
    watcher.run()
