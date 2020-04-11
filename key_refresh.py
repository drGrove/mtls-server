import time
import threading


class KeyRefresh(object):
    def __init__(self, gnupg, config):
        self.interval = int(config.get('gnupg', 'sync_interval', fallback=600))
        self.gnupg = gnupg
        self.config = config
        self.paused = False
        thread = threading.Thread(target=self.run, args=())
        thread.daemon = True
        thread.start()
        self.thread = thread

    def run(self):
        print("Attempting to run")
        while not self.paused:
            keyserver = self.config.get(
                'gnupg',
                'keyserver',
                fallback='keyserver.ubuntu.com'
            )
            print(f"Refreshing PGP Keys from {keyserver} for {self.gnupg.gnupghome}")
            current_keys = self.gnupg.list_keys()
            key_ids = list(map(lambda x: x['keyid'], current_keys))
            keys = self.gnupg.recv_keys(keyserver, *key_ids)
            print(f"Refreshed {keys.count}/{len(current_keys)} from {keyserver}")
            time.sleep(self.interval)

    def suspend(self):
        self.paused = True

    def resume(self):
        self.paused = False

    def active(self):
        return self.thread.is_alive()
