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
from browsers.general import general

class firefox(general):

    config = {
        'files' : {
            'histories' : 'places.sqlite',
            'passwords' : 'logins.json',
            'cookies' : 'cookies.sqlite'
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

    def _convert_datetime_to_timestamp(self, datetime_input):
        input_date = datetime.strptime(datetime_input, '%Y/%m/%d-%H:%M:%S')
        epoch = datetime.utcfromtimestamp(0)
        return int((input_date - epoch).total_seconds() * 1000000)

    def history(self, profile_path, filters=None):

        query_conditions = []
        if filters.get('from_date') != None:
            # if input just have date
            from_date = filters.get('from_date')
            if self.validate_simple_date_format(from_date):
                from_date += '-00:00:00'

            try:
                query_conditions.append('last_visit_date >='+ str(self._convert_datetime_to_timestamp(from_date)))
            except Exception as e:
                print('[-] from_date filter error : {}'.format(e))
                exit()

        if filters.get('to_date') != None:
            # if input just have date
            to_date = filters.get('to_date')
            if self.validate_simple_date_format(to_date):
                to_date += '-23:59:59'

            try:
                query_conditions.append('last_visit_date <='+ str(self._convert_datetime_to_timestamp(to_date)))
            except Exception as e:
                print('[-] to_date filter error : {}'.format(e))
                exit()

        if filters.get('total_visit') != None:
            query_conditions.append('visit_count >='+ filters.get('total_visit'))

        sql_query = "SELECT url, visit_count, datetime(last_visit_date/1000000,'unixepoch'), title FROM moz_places"
        if query_conditions:
            sql_query += ' WHERE '+ ' and '.join(query_conditions)
        sql_query += ' ORDER BY visit_count'

        try:
            connection = sqlite3.connect(os.path.join(profile_path, self.config['files']['histories']))
            db_cursor = connection.cursor()
            db_cursor.execute(sql_query)
            urls = db_cursor.fetchall()
            parsed_histories = []
            for url in urls:
                parsed_histories.append({
                    'url' : url[0],
                    'title' : url[3],
                    'count' : str(url[1]),
                    'last_visit' : str(url[2])
                })
            db_cursor.close()
            return {'status': True, 'data': parsed_histories}
        except Exception as error:
            return {'status': False, 'data': str(error)}

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
                profiles.append({'path' : os.path.join(self.profiles_path, profile), 'name': profile, 'browser': self.__class__.__name__})
        return profiles