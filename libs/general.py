### LICENCE ###
# This file is part of Infornito project.
# Infornito is a free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation.
# Infornito is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details: <http://www.gnu.org/licenses/>

### ABOUT Infornito ###
# Infornito is browser forensic tool
# Copyright (C) GlobeCyber <Github@GlobeCyber.com>

### DISCLAIMER ###
# We are not responsible for misuse of Infornito
# Making a DNS tunnel to bypass a security policy may be forbidden
# Do it at your own risks

import platform
import os
import hashlib

class general():
    def __init__(self):
        self.platform_name = platform.system().lower()
        self.user_home = os.environ['HOME']

    def set_profiles_path(self, path):
        self.profiles_path = path

    def sha256sum(self, filepath):
        h  = hashlib.sha256()
        b  = bytearray(128*1024)
        mv = memoryview(b)
        with open(filepath, 'rb', buffering=0) as f:
            for n in iter(lambda : f.readinto(mv), 0):
                h.update(mv[:n])
        return h.hexdigest()

    def md5sum(self, filepath):
        BLOCKSIZE = 65536
        hasher = hashlib.md5()
        with open(filepath, 'rb') as source:
            buf = source.read(BLOCKSIZE)
            while len(buf) > 0:
                hasher.update(buf)
                buf = source.read(BLOCKSIZE)
        return hasher.hexdigest()

    def sha1sum(self, filepath):
        hasher = hashlib.sha1()
        with open(filepath, 'rb') as source:
            block = source.read(2**16)
            while len(block) != 0:
                hasher.update(block)
                block = source.read(2**16)
        return hasher.hexdigest()

    def file_fingerprint(self, filepath):
        output = {
            'md5' : self.md5sum(filepath),
            'sha1' : self.sha1sum(filepath),
            'sha256' : self.sha256sum(filepath)
        }
        return output