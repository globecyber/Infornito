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

import sqlite3
import os
import datetime
from libs.general import general

class chrome(general):
    config = {
        'files' : {
            'histories' : 'History',
            'passwords' : 'Login Data',
            'cookies' : 'Cookies',
            'autofills' : 'Web Data'
        },
        'platform_profile_path' : {
            'darwin' : 'Library/Application Support/Google/Chrome',
            'windows': 'AppData\\Local\\Google\\Chrome\\User Data'
        }
    }

    def __init__(self):
        general.__init__(self)
        self.profiles_path = os.path.join(self.user_home, self.config['platform_profile_path'][self.platform_name])

    # Private Methods
    def _convert_date_from_webkit(self, webkit_timestamp):
        epoch_start = datetime.datetime(1601,1,1)
        delta = datetime.timedelta(microseconds=int(webkit_timestamp))
        return epoch_start + delta

    def downloads(self, profile_path):
        # TODO : Filtering By : ['fileextension', 'date', 'daterange', 'domain']
        try:
            connection = sqlite3.connect(os.path.join(profile_path, self.config['files']['histories']))
            db_cursor = connection.cursor()
            downloaded_files = db_cursor.execute("SELECT tab_url, target_path, start_time, total_bytes, state FROM downloads;").fetchall()
            downloads = []
            for download_item in downloaded_files:

                is_fully_download = False
                if download_item[4] == 1:
                    is_fully_download = True

                downloads.append({
                    'url' : download_item[0],
                    'saved_in' : str(download_item[1]),
                    'start_downloading_at' : str(self._convert_date_from_webkit(download_item[2])),
                    'size' : download_item[3],
                    'is_fully_download' : is_fully_download
                })

            db_cursor.close()

            return downloads   
        except Exception as error:
            print('Error : ' + str(error))
            exit()

    def history(self, profile_path):
        try:
            connection = sqlite3.connect(os.path.join(profile_path, self.config['files']['histories']))
            db_cursor = connection.cursor()
            db_cursor.execute("SELECT url, visit_count, last_visit_time FROM urls ORDER BY visit_count;")
            urls = db_cursor.fetchall()
            parsed_histories = []
            for url in urls:
                parsed_histories.append({
                    'url' : url[0],
                    'count' : str(url[1]),
                    'last_visit' : str(self._convert_date_from_webkit(url[2]))
                })
            db_cursor.close()
            return {'status': True, 'data': parsed_histories}
        except Exception as error:
            return {'status': False, 'data': str(error)}

    def get_profiles(self):
        profiles = []

        if os.path.isdir(self.profiles_path):
            for profile in os.listdir(self.profiles_path):
                if(profile == 'Default' or 'Profile' in profile):
                    profiles.append({'path' : os.path.join(self.profiles_path,profile), 'name': profile, 'browser': self.__class__.__name__})

        return profiles
