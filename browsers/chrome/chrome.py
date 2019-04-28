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
from browsers.general import general

class chrome(general):
    config = {
        'files' : {
            'histories' : 'History',
            'passwords' : 'Login Data',
            'cookies' : 'Cookies',
            'autofills' : 'Web Data',
            'configurations' : 'Preferences',
            'favicons' : 'Favicons',
            'bookmarks' : 'Bookmarks',
            'current_session' : 'Current Session',
            'last_session' : 'Last Session',
            'current_tabs' : 'Current Tabs',
            'last_tabs' : 'Last Tabs'
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
    def _convert_timestamp_to_datetime(self, timestamp_input):
        epoch_start = datetime.datetime(1601,1,1)
        delta = datetime.timedelta(microseconds=int(timestamp_input))
        return epoch_start + delta

    def _convert_datetime_to_timestamp(self, datetime_input):
        epoch_start = datetime.datetime(1601, 1, 1)
        date_ = datetime.datetime.strptime(datetime_input, '%Y/%m/%d-%H:%M:%S')
        diff = date_ - epoch_start
        seconds_in_day = 60 * 60 * 24
        return '{:<017d}'.format(
            diff.days * seconds_in_day + diff.seconds + diff.microseconds)

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
                    'start_downloading_at' : str(self._convert_timestamp_to_datetime(download_item[2])),
                    'size' : download_item[3],
                    'is_fully_download' : is_fully_download
                })

            db_cursor.close()

            return downloads   
        except Exception as error:
            print('Error : ' + str(error))
            exit()

    def history(self, profile_path, filters={}):

        query_conditions = []
        if filters.get('from_date') != None:
            # if input just have date
            from_date = filters.get('from_date')
            if self.validate_simple_date_format(from_date):
                from_date += '-00:00:00'

            try:
                query_conditions.append('last_visit_time >='+ str(self._convert_datetime_to_timestamp(from_date)))
            except Exception as e:
                print('[-] from_date filter error : {}'.format(e))
                exit()

        if filters.get('to_date') != None:
            # if input just have date
            to_date = filters.get('to_date')
            if self.validate_simple_date_format(to_date):
                to_date += '-23:59:59'

            try:
                query_conditions.append('last_visit_time <='+ str(self._convert_datetime_to_timestamp(to_date)))
            except Exception as e:
                print('[-] to_date filter error : {}'.format(e))
                exit()

        if filters.get('total_visit') != None:
            query_conditions.append('visit_count >='+ filters.get('total_visit'))
        
        try:
            sql_query = "SELECT url, visit_count, last_visit_time, title FROM urls"
            if query_conditions:
                sql_query += ' WHERE '+ ' and '.join(query_conditions)
            sql_query += ' ORDER BY visit_count'

            connection = sqlite3.connect(os.path.join(profile_path, self.config['files']['histories']))
            db_cursor = connection.cursor()
            db_cursor.execute(sql_query)
            urls = db_cursor.fetchall()
            parsed_histories = []
            for url in urls:
                parsed_histories.append({
                    'url' : url[0],
                    'title' : str(url[3]),
                    'count' : str(url[1]),
                    'last_visit' : str(self._convert_timestamp_to_datetime(url[2]))
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
