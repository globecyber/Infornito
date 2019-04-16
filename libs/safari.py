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
import plistlib
from libs.general import general

class safari(general):
    config = {
        'files' : {
            'histories' : 'History.db',
            'downloads' : 'Downloads.plist'
        },
        'platform_profile_path' : {
            'darwin' : 'Library/Safari/',
        }
    }

    def __init__(self):
        general.__init__(self)
        self.profiles_path = os.path.join(self.user_home, self.config['platform_profile_path'][self.platform_name])

    def history(self, profile_path):
        try:
            connection = sqlite3.connect(os.path.join(profile_path, self.config['files']['histories']))
            db_cursor = connection.cursor()
            db_cursor.execute("SELECT url, visit_count FROM history_items ORDER BY visit_count;")
            urls = db_cursor.fetchall()
            parsed_histories = []
            for url in urls:
                parsed_histories.append({
                    'url' : url[0],
                    'count' : str(url[1]),
                })
            db_cursor.close()
            return parsed_histories        
        except Exception as error:
            print('Error : ' + str(error))
            exit()

    def downloads(self, profile_path):
        try:
            downloaded_files = plistlib.readPlist(os.path.join(profile_path, self.config['downloads']))
            downloads = []
            for download_item in downloaded_files['DownloadHistory']:
                is_fully_download = False
                if download_item['DownloadEntryProgressBytesSoFar'] ==  download_item['DownloadEntryProgressTotalToLoad']:
                    is_fully_download = True
                
                downloads.append({
                    'url' : download_item['DownloadEntryURL'],
                    'saved_in' : download_item['DownloadEntryPath'].split('.download')[0],
                    'start_downloading_at' : str(download_item['DownloadEntryDateAddedKey']),
                    'size' : str(download_item['DownloadEntryProgressTotalToLoad']),
                    'is_fully_download' : is_fully_download
                })

            return downloads   
        except Exception as error:
            print('Error : ' + str(error))
            exit()

    def get_profiles(self):
        profiles = []
        if os.path.isdir(self.profiles_path):
            profiles.append({'path' : self.profiles_path, 'name': 'Default', 'browser': self.__class__.__name__})
        return profiles
