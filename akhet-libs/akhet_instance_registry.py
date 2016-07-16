import threading
import random
import string

from akhet_logger import akhet_logger

class AkhetInstanceRegistry(object):
    instanceRegistry = None
    locker = None

    def __init__(self):
        self.instanceRegistry = {}
        self.locker = threading.Lock()

    def get(self, token):
        if token in self.instanceRegistry:
            return self.instanceRegistry[token]
        else:
            return None

    def lock(self):
        self.locker.acquire()

    def unlock(self):
        self.locker.release()

    def add_data(self,token,data):
        if token in self.instanceRegistry:
            if len(self.instanceRegistry[token]) == 0:
                self.lock()
                self.instanceRegistry[token] = data
                self.unlock()

    def update_data(self,token,data,doLock=True):
        if token in self.instanceRegistry:
            if len(self.instanceRegistry[token]) != 0:
                if doLock:
                    self.lock()
                self.instanceRegistry[token] = data
                self.unlock()


    def delete_data(self,token):
        if token in self.instanceRegistry:
            self.lock()
            del self.instanceRegistry[token]
            self.unlock()

    def get_token(self):
        self.lock()

        ok_to_add = False
        while not ok_to_add:
            new_token = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(32))
            if new_token not in self.instanceRegistry:
                ok_to_add = True
        self.instanceRegistry[new_token] = {}

        self.unlock()
        return new_token
