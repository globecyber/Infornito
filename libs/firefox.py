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
import json

from datetime import datetime
from libs.general import general

class firefox(general):

    config = {
        'files' : {
            'histories' : 'places.sqlite',
            'passwords' : 'logins.json',
        },
        'platform_profile_path' : {
            'windows' : 'AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\',
            'darwin' : 'Library/Application Support/Firefox/Profiles',
            'linux' : '.mozilla/firefox/Profiles/'
        }
    }

    def __init__(self):
        general.__init__(self)
        self.profiles_path = os.path.join(self.user_home, self.config['platform_profile_path'][self.platform_name])

    def history(self, profile_path, filters=None):
        query_filters = ""
        if filters:
            query_filters = " WHERE "
            if filters.get('domain'):
                query_filters += "url LIKE 'http'"

        query = "SELECT url, visit_count, datetime(last_visit_date/1000000,'unixepoch') FROM moz_places"+query_filters+' ORDER BY visit_count;'
        print(query)
        # try:
        connection = sqlite3.connect(os.path.join(profile_path, self.config['files']['histories']))
        db_cursor = connection.cursor()
        db_cursor.execute(query)
        urls = db_cursor.fetchall()
        parsed_histories = []
        for url in urls:
            parsed_histories.append({
                'url' : url[0],
                'count' : str(url[1]),
                'last_visit' : str(url[2])
            })
        db_cursor.close()
        return parsed_histories        
        # except Exception as error:
        #     print('Error : ' + str(error))
        #     exit()

    def downloads(self, profile_path):
        try:
            connection = sqlite3.connect(os.path.join(profile_path, self.config['files']['histories']))
            db_cursor = connection.cursor()
            downloaded_files = db_cursor.execute("SELECT places.url, basic_info.content, basic_info.dateAdded, extended_info.content FROM moz_annos AS basic_info JOIN moz_annos AS extended_info ON basic_info.place_id=extended_info.place_id JOIN moz_places as places ON basic_info.place_id=places.id WHERE basic_info.anno_attribute_id='4' AND extended_info.anno_attribute_id='6'").fetchall()
        
            downloads = []
            for url in downloaded_files:
                download_metadata = json.loads(url[3])

                is_fully_download = False
                if download_metadata['state'] == 1:
                    is_fully_download = True
                
                filesize = download_metadata.get('fileSize')
                downloads.append({
                    'url' : url[0],
                    'saved_in' : str(url[1][7:]),
                    'start_downloading_at' : datetime.fromtimestamp(float(url[2])/1000000.0).strftime('%Y-%m-%d %H:%M:%S'),
                    'filesize' : filesize,
                    'is_fully_download' : is_fully_download
                })

            db_cursor.close()
            return downloads

        except Exception as error:
            print('Error : ' + str(error))
            exit()
    
    def get_profiles(self):
        profiles = []
        if os.path.isdir(self.profiles_path):
            for profile in os.listdir(self.profiles_path):
                profiles.append({'path' : self.profiles_path + '/' + profile, 'name': profile, 'browser': self.__class__.__name__})
        return profiles