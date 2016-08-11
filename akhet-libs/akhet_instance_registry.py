import threading
import random
import string

from akhet_logger import akhet_logger

class AkhetInstanceRegistry(object):
    instance_registry = None
    locker = None

    def __init__(self):
        self.instance_registry = {}
        self.locker = threading.Lock()

    def get(self, token):
        if token in self.instance_registry:
            return self.instance_registry[token]
        else:
            return None

    def lock(self):
        self.locker.acquire()

    def unlock(self):
        self.locker.release()

    def add_data(self,token,data):
        if token in self.instance_registry and len(self.instance_registry[token]) == 0:
            self.lock()
            self.instance_registry[token] = data
            self.unlock()

    def update_data(self,token,data,do_lock=True):
        if token in self.instance_registry and len(self.instance_registry[token]) != 0:
            if do_lock:
                self.lock()
            self.instance_registry[token] = data
            self.unlock()


    def delete_data(self,token):
        if token in self.instance_registry:
            self.lock()
            del self.instance_registry[token]
            self.unlock()

    def get_token(self):
        self.lock()

        ok_to_add = False
        while not ok_to_add:
            new_token = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(32))
            if new_token not in self.instance_registry:
                ok_to_add = True
        self.instance_registry[new_token] = {}

        self.unlock()
        return new_token
