import platform
import os
import hashlib

class general():
    def __init__(self):
        self.platform_name = platform.system().lower()
        self.user_home = os.environ['HOME']

    def set_profiles_path(self, path):
        self.profiles_path = path

    def sha256sum(self, filename):
        h  = hashlib.sha256()
        b  = bytearray(128*1024)
        mv = memoryview(b)
        with open(filename, 'rb', buffering=0) as f:
            for n in iter(lambda : f.readinto(mv), 0):
                h.update(mv[:n])
        return h.hexdigest()

    def md5sum(self, filename):
        BLOCKSIZE = 65536
        hasher = hashlib.md5()
        with open(filename, 'rb') as source:
            buf = source.read(BLOCKSIZE)
            while len(buf) > 0:
                hasher.update(buf)
                buf = source.read(BLOCKSIZE)
        return hasher.hexdigest()

    def sha1sum(self, filename):
        hasher = hashlib.sha1()
        with open(filename, 'rb') as source:
            block = source.read(2**16)
            while len(block) != 0:
                hasher.update(block)
                block = source.read(2**16)
        return hasher.hexdigest()