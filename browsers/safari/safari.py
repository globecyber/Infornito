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
import platform
import plistlib
import datetime
from browsers.general import general

class safari(general):
    config = {
        'files' : {
            'histories' : 'History.db',
            'downloads' : 'Downloads.plist',
            'cookies' : 'Library/Cookies/Cookies.binarycookies'
        },
        'platform_profile_path' : {
            'darwin' : 'Library/Safari/',
        }
    }

    def __init__(self):
        general.__init__(self)
        if platform.system().lower() == 'darwin':
            self.profiles_path = os.path.join(self.user_home, self.config['platform_profile_path'][self.platform_name])

    def _convert_datetime_to_timestamp(self, datetime_input):
        input_date = datetime.datetime.strptime(datetime_input, '%Y/%m/%d-%H:%M:%S')
        epoch = datetime.datetime.utcfromtimestamp(0)
        return int((input_date - epoch).total_seconds() - 978307200)

    def _convert_timestamp_to_datetime(self, timestamp_input):
        correct_timestamp = timestamp_input + 978307200
        return datetime.datetime.utcfromtimestamp(correct_timestamp).strftime("%Y-%m-%d %H:%M:%S")
    
    def history(self, profile_path, filters=None):

        query_conditions = []
        if filters.get('from_date') != None:
            # if input just have date
            from_date = filters.get('from_date')
            if self.validate_simple_date_format(from_date):
                from_date += '-00:00:00'

            try:
                query_conditions.append('extended_info.visit_time >='+ str(self._convert_datetime_to_timestamp(from_date)))
            except Exception as e:
                print('[-] from_date filter error : {}'.format(e))
                exit()

        if filters.get('to_date') != None:
            # if input just have date
            to_date = filters.get('to_date')
            if self.validate_simple_date_format(to_date):
                to_date += '-23:59:59'

            try:
                query_conditions.append('extended_info.visit_time <='+ str(self._convert_datetime_to_timestamp(to_date)))
            except Exception as e:
                print('[-] to_date filter error : {}'.format(e))
                exit()

        if filters.get('total_visit') != None:
            query_conditions.append('basic_info.visit_count >='+ filters.get('total_visit'))

        sql_query = "SELECT basic_info.url, basic_info.visit_count, extended_info.visit_time, extended_info.title FROM history_items AS basic_info JOIN history_visits AS extended_info ON basic_info.id=extended_info.history_item"
        if query_conditions:
            sql_query += ' WHERE '+ ' and '.join(query_conditions)
        sql_query += ' ORDER BY basic_info.visit_count'

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
                    'last_visit' : self._convert_timestamp_to_datetime(url[2])
                })
            db_cursor.close()
            return {'status': True, 'data': parsed_histories}
        except Exception as error:
            return {'status': False, 'data': str(error)}

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
