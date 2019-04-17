#!/usr/bin/env python3

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

import os
import json
import argparse
import re
import urllib.parse
from shutil import copyfile
from datetime import datetime
from tabulate import tabulate
from libs.firefox import firefox
from libs.chrome import chrome
from libs.safari import safari


def banner():
    print('''
  _______     __       _____     __          
 / ___/ /__  / /  ___ / ___/_ __/ /  ___ ____
/ (_ / / _ \/ _ \/ -_) /__/ // / _ \/ -_) __/
\___/_/\___/_.__/\__/\___/\_, /_.__/\__/_/   
                         /___/               
            < Infornito v0.4 >
''')

browser_modules = {
    'firefox': firefox(), 
    'chrome': chrome(), 
    'safari': safari()
}

def _urldecode(string):
    return urllib.parse.unquote(string)

def profile_info(profile_id=None):
    browsers_profiles_data = []
    for browser_name, browser_module in browser_modules.items():
        for profile in browser_module.get_profiles():
            browsers_profiles_data.append(profile)

    if profile_id:
        try:
            browsers_profiles_data[0]['id'] = profile_id
            return browsers_profiles_data[int(profile_id)-1]
        except:
            print('[-] Profile id not found.')
            exit()
    else:
        return browsers_profiles_data

def parse_filters(filter_list):
    if filter_list:
        filters = {}
        for filter_item in filter_list:
            if '=' in filter_item:
                extract_filter = filter_item.split('=')
                filters[extract_filter[0]] = extract_filter[1]
            else:
                filters[filter_item] = True
        
        return filters
    return None

def arg_fingerprint(args):

    profile_information = profile_info(int(args.profile[0]))
    browser_type = profile_information['browser']

    print('[~] Profile path : {}\n'.format(profile_information['path']))
    fingerprint_files = browser_modules[browser_type].fingerprint(profile_information['path'])
    for filename, fingerprints in fingerprint_files.items():
        print('[+] ' + filename)
        for algorithm, fingerprint in fingerprints.items():
            print('\t{} : {}'.format(algorithm, fingerprint))

def export_profile(profile_id):
    profile_information = profile_info(profile_id)
    export_path = args.to[0]
    current_time = datetime.utcnow().strftime('%Y-%m-%d %H-%M-%S')
    final_path = os.path.join(export_path, profile_information['browser'].capitalize(), profile_information['name'], current_time)
    browser_files = browser_modules[profile_information['browser']].config['files']
    # Create folder with profile name if not exist
    if not os.path.exists(final_path):
        os.makedirs(final_path)
    
    print('\n==== [{}] {} ({}) ===='.format(profile_id, profile_information['browser'].capitalize(), profile_information['name']))
    print('[~] Profile path : {}'.format(profile_information['path']))
    print('[~] Destination path : {}'.format(final_path))
    print('[~] Start exporting profile files ...')
    # Copy important file to export path
    for (name, filename) in browser_files.items():
        print('\t[+] Exporting {} : '.format(filename), end='')
        try:
            copyfile(os.path.join(profile_information['path'], filename), os.path.join(final_path, filename))
            print('Successful')
        except:
            print('Failed')
    
    # Create infornito metadata
    print('\t[+] Creating infornito.json : ', end='')
    try:
        metadata = {
            'machine_name' : os.uname().nodename,
            'platform' : os.uname().sysname,
            'platform_version' : os.uname().version,
            'arch' : os.uname().machine,
            'export_time' : datetime.utcnow().strftime("%s"),
            'files' : browser_modules[profile_information['browser']].fingerprint(profile_information['path'])
        }

        with open(os.path.join(final_path, 'infornito.json'), 'w') as outfile:  
            json.dump(metadata, outfile)
        print('Successful')
    except:
        print('Failed')

def arg_export(args):
    # Export all profiles if profile id not mentioned
    if args.profile == None:
        profiles = profile_info()
        for profile_id in range(1,len(profiles)+1):
            export_profile(profile_id)
    else:
        export_profile(args.profile[0])

def arg_history(args):
    profile_information = profile_info(int(args.profile[0]))
    browser_type = profile_information['browser']
    history = browser_modules[browser_type].history(profile_information['path'])
    query_filters = parse_filters(args.filter)

    if args.urldecode or query_filters.get('xss') or query_filters.get('lfi') or query_filters.get('sqli'):
        for index, item in enumerate(history):
            history[index]['url'] = _urldecode(item['url'])
    
    # Filter Output
    if query_filters != None:

        if query_filters.get('ip'):
            if query_filters.get('ip') == True :
                history = [item for item in history if re.search(r'^(https?:\/\/)?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d{1,5})?(\/.*)?$', item['url'])]
            elif query_filters.get('ip') == 'lan' :
                history = [item for item in history if re.search(r'^(https?:\/\/)?((127\.\d{1,3}\.\d{1,3}\.\d{1,3})|(192\.168\.\d{1,3}\.\d{1,3})|(10\.\d{1,3}\.\d{1,3}\.\d{1,3})|(172\.1[6-9]\.\d{1,3}\.\d{1,3})|(172\.2[0-9]\.\d{1,3}\.\d{1,3})|(172\.3[0-1]\.\d{1,3}\.\d{1,3}))(:\d{1,5})?(\/.*)?$', item['url'])]
            else:
                history = [item for item in history if re.search(r'^(https?:\/\/)?('+query_filters.get('ip').replace(',','|')+')(:\d{1,5})?(\/.*)?$', item['url'])]

        if query_filters.get('tld'):
            history = [item for item in history if re.search(r'^(https?:\/\/)?(\w*\.)*(' + query_filters.get('tld').replace(',','|') + ')(\/.*)?$', item['url'])]

        if query_filters.get('regex'):
            history = [item for item in history if re.search(query_filters.get('regex'), item['url'])]

    # Print Outputs
    for item in history:
        if item.get('last_visit'):
            print('[{}] {} ( {} )'.format(item['count'], item['url'], item['last_visit']))
        else:
            print('[{}] {}'.format(item['count'], item['url']))
    print('\n[Total visit] URL ( Last Visit )')
    print('----------------- Summary ----------------')
    print('Total url : {}'.format(len(history)))

def arg_profiles(args):
    print('Profiles :\n')
    browser_profile_list = []
    try:
        profiles = profile_info(args.id[0])
    except:
        profiles = profile_info()

    if args.id:
            browser_profile_list.append([args.id[0], profiles['name'], profiles['browser'].capitalize()])
    else:
        for (key, profile_information) in enumerate(profiles):
            browser_profile_list.append([key+1, profile_information['name'], profile_information['browser'].capitalize()])

    print(tabulate(browser_profile_list, headers=['ID', 'Profile Name', 'Browser Type']),'\n')
    print('Example : python3 infornito.py history -pid {ProfileID}')

def arg_downloads(args):
    profile_information = profile_info(int(args.profile[0]))
    browser_type = profile_information['browser']
    downloads = browser_modules[browser_type].downloads(profile_information['path'])
    for item in downloads:
        status = '+'
        if not item['is_fully_download']:
            status = '-'

        print('[{}] {} -> {} ( {} )'.format(status, item['url'], item['saved_in'], item['start_downloading_at']))
    print('\n----------------- Summary ----------------')
    print('[#] Total downloads : {}'.format(len(downloads)))

banner()

parser = argparse.ArgumentParser(description='Simple browser forensic tool')
subparsers = parser.add_subparsers()

profiles = subparsers.add_parser('profiles', description='Simple browser forensic tool')
profiles.add_argument('--id', nargs=1, help='Select profile id')
profiles.set_defaults(func=arg_profiles)

history = subparsers.add_parser('history')
history.add_argument('--profile', nargs=1, help='Select profile id')
history.add_argument('--filter', action='append', help='add filter')
history.add_argument('--urldecode', action='store_true', help='url decode hisotries')
history.set_defaults(func=arg_history)

fingerprint = subparsers.add_parser('fingerprint')
fingerprint.add_argument('--profile', nargs=1, help='Select profile id')
fingerprint.set_defaults(func=arg_fingerprint)

downloads = subparsers.add_parser('downloads')
downloads.add_argument('--profile', nargs=1, help='Select profile id')
downloads.set_defaults(func=arg_downloads)

export = subparsers.add_parser('export')
export.add_argument('--profile', nargs=1, help='Select profile id')
export.add_argument('--to', nargs=1, default=['export'], help='Destination path for export profile')
export.set_defaults(func=arg_export)

args = parser.parse_args()
try:
    args.func(args)
except AttributeError:
    parser.error("too few arguments")