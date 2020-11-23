import time
import threading

from .logger import logger


class KeyRefresh(object):
    def __init__(self, name, gnupg, config):
        logger.info(f"KeyRefresh: init background thread for {name}")
        self.name = name
        self.interval = config.get_int('gnupg', 'sync_interval', 600)
        self.gnupg = gnupg
        self.config = config
        self.paused = False
        thread = threading.Thread(name=name, target=self.run, args=())
        thread.daemon = True
        thread.start()
        self.thread = thread

    def run(self):
        logger.info(f"KeyRefresh: {self.name} | run loop")
        while not self.paused:
            keyserver = self.config.get('gnupg', 'keyserver', 'keyserver.ubuntu.com')
            logger.info(f"KeyRefresh: {self.name} | Refreshing PGP Keys from {keyserver} for {self.gnupg.gnupghome}")
            current_keys = self.gnupg.list_keys()
            key_ids = list(map(lambda x: x['keyid'], current_keys))
            keys = self.gnupg.recv_keys(keyserver, *key_ids)
            logger.info(f"KeyRefresh {self.name} | Refreshed {keys.count}/{len(current_keys)} from {keyserver}")
            time.sleep(self.interval)

    def suspend(self):
        self.paused = True

    def resume(self):
        self.paused = False

    def active(self):
        return self.thread.is_alive()
