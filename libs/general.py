import platform
import os

class general():
    def __init__(self):
        self.platform_name = platform.system().lower()
        self.user_home = os.environ['HOME']

    def set_profiles_path(self, path):
        self.profiles_path = path