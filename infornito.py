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
import sys
import json
import argparse
import platform
import re
import urllib.parse
import urllib.request
import zipfile
import glob
import html
from shutil import copyfile, copyfileobj
from datetime import datetime
from browsers.firefox import firefox
from browsers.chrome import chrome
from browsers.safari import safari
from libs.exporter import export_csv
import libs.filterer as filterer
from libs.general import copyDirectory

__version__ = 1.4

def banner():
    print('''
  _______     __       _____     __          
 / ___/ /__  / /  ___ / ___/_ __/ /  ___ ____
/ (_ / / _ \/ _ \/ -_) /__/ // / _ \/ -_) __/
\___/_/\___/_.__/\__/\___/\_, /_.__/\__/_/   
                         /___/               
            < Infornito v{} >
'''.format(__version__))

templates_path = os.path.join(os.getcwd(), 'templates')
default_export_path = './exports'
browser_modules = {
    'firefox': firefox(), 
    'chrome': chrome(), 
    'safari': safari()
}

def _urldecode(string):
    return urllib.parse.unquote(string)

def _urlencode(string):
    return urllib.parse.quote(string)

def profile_info(profile_id=None):

    browsers_profiles_data = []
    for browser_name, browser_module in browser_modules.items():
        if browser_name == 'safari' and platform.system().lower() != 'darwin':
            continue

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
    return {}

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
        except Exception as e:
            print('Failed' + str(e))
    
    # Create infornito metadata
    print('\t[+] Creating infornito.json : ', end='')
    try:
        metadata = {
            'machine_name' : os.getlogin(),
            'platform' : platform.system().lower(),
            'platform_version' : platform.platform(),
            'export_time' : datetime.utcnow().timestamp(),
            'files' : browser_modules[profile_information['browser']].fingerprint(profile_information['path'])
        }

        with open(os.path.join(final_path, 'infornito.json'), 'w') as outfile:  
            json.dump(metadata, outfile)
        print('Successful')
    except Exception as e:
        print('Failed' + str(e))

def arg_export(args):
    # Export all profiles if profile id not mentioned
    if args.profile == None:
        profiles = profile_info()
        for profile_id in range(1,len(profiles)+1):
            export_profile(profile_id)
    else:
        export_profile(args.profile[0])

def get_history(profile_id, filters={}):
    profile_information = profile_info(profile_id)
    history = browser_modules[profile_information['browser']].history(profile_information['path'], filters)
    return history

def arg_history(args):

    query_filters = parse_filters(args.filter)
    history = []
    if args.profile == None:
        print('[~] Getting profiles history ...')
        profiles = profile_info()
        for profile_id in range(1,len(profiles)+1):
            history_response = get_history(profile_id, filters=query_filters)
            if not history_response['status']:
                print('[-] Profile #{} : {}'.format(profile_id, history_response['data']))
            else:
                history += history_response['data']
    else:
        history_response = get_history(str(args.profile[0]), filters=query_filters)
        if not history_response['status']:
            print('[-] {}'.format(history_response['data']))
            exit()
        
        history = history_response['data']

    if args.urldecode or query_filters.get('xss') or query_filters.get('lfi') or query_filters.get('sqli'):
        for index, item in enumerate(history):
            history[index]['url'] = _urldecode(item['url'])
    
    # Filter Output
    if query_filters != None:

        if query_filters.get('ip'):
            if query_filters.get('ip') == True :
                history = [item for item in history if filterer.ip_equal(item['url'])]
            elif query_filters.get('ip') == 'lan' :
                history = [item for item in history if filterer.ip_equal(item['url'], 'lan')]
            else:
                history = [item for item in history if filterer.ip_equal(item['url'], query_filters.get('ip'))]

        if query_filters.get('tld'):
            history = [item for item in history if filterer.tld_equal(item['url'], query_filters.get('tld'))]

        if query_filters.get('regex'):
            history = [item for item in history if re.search(query_filters.get('regex'), item['url'])]

        if query_filters.get('domain'):
            history = [item for item in history if filterer.domain_equal(item['url'], query_filters.get('domain'))]

        if query_filters.get('protocol'):
            history = [item for item in history if filterer.protocol_equal(item['url'], query_filters.get('protocol'))]
    
        if query_filters.get('filetype'):
            history = [item for item in history if filterer.filetype_equal(item['url'], query_filters.get('filetype'))]

        if query_filters.get('port'):
            history = [item for item in history if filterer.port_equal(item['url'], query_filters.get('port'))]

        if query_filters.get('wordpress') == True :
            history = [item for item in history if filterer.is_wordpress(item['url'])]

        if query_filters.get('adminpanel') == True :
            history = [item for item in history if filterer.is_adminpanel(item['url'])]

        if query_filters.get('localfile') == True :
            history = [item for item in history if filterer.is_localfile(item['url'])]

        if query_filters.get('xss') == True :
            history = [item for item in history if filterer.is_xss_attack(item['url'])]

        if query_filters.get('sqli') == True :
            history = [item for item in history if filterer.is_sqli_attack(item['url'])]
        
        if query_filters.get('lfi') == True :
            history = [item for item in history if filterer.is_lfi_attack(item['url'])]

        if query_filters.get('social') == True :
            history = [item for item in history if filterer.is_social(item['url'])]

        if query_filters.get('technical') == True :
            history = [item for item in history if filterer.is_technical(item['url'])]

        if query_filters.get('storage') == True :
            history = [item for item in history if filterer.is_storage(item['url'])]

    if args.export != None:

        export_type = args.export[0]
        print('[~] Exporting history to {} file ...'.format(export_type))
        current_time = datetime.utcnow().strftime('%Y-%m-%d %H-%M-%S')
        export_path = default_export_path
        if args.to != None:
            export_path = args.to[0]
        final_path = os.path.join(export_path, current_time)

        print('\t[+] Export path : {}'.format(final_path))

        if export_type == 'html':

            try:
                if not os.path.exists(templates_path):
                    os.makedirs(templates_path)
                
                if not os.path.exists(os.path.join(templates_path, 'html')):
                    print('[!] html template not found, trying to download template ...')
                    html_template_url = 'https://github.com/globecyber/InfornitoExportTemplates/raw/master/html.zip'
                    local_html_template_path = os.path.join(templates_path, 'html.zip')
                    try:
                        if not os.path.exists(local_html_template_path):
                            # Download template
                            with urllib.request.urlopen(html_template_url) as response, open(local_html_template_path, 'wb') as out_file:
                                copyfileobj(response, out_file)
                            print('\t[+] html template downloaded successfully.')
                        print('\t[~] extracting template ...')
                        # Extract Template
                        zip = zipfile.ZipFile((local_html_template_path))
                        zip.extractall(os.path.join(templates_path, 'html'))
                        zip.close()
                        # Remove compressed file
                        os.remove(os.path.join(local_html_template_path))
                    except Exception as e:
                        print('\t[-]' + str(e))
                        print('\t[!] if you have any problem during download, you can download template from {} and extract it to {}.'.format(html_template_url, templates_path))
                        exit()

                with open(os.path.join(templates_path, 'html', 'history.template.html'), "r") as f:
                    output_template = f.read()
                
                output_list = []
                for item in history:
                    temp = [html.escape(item['url']), html.escape(str(item['title'])), item['count'], item['last_visit']]
                    output_list.append(temp)

                output_html = output_template.replace('%OUTPUT_DATA%', json.dumps(output_list))
                output_html = output_html.replace('%COMMAND%', ' '.join(sys.argv))
                
                # Copy template to destination
                copyDirectory(os.path.join(templates_path, 'html'), final_path)
                # Remove template file
                for item in glob.glob(os.path.join(final_path, "*.template.html")):
                    os.remove(item)
                # Save output
                output_file = open(os.path.join(final_path, 'history.html'), "w")
                output_file.write(output_html)
                output_file.close()
                print('\t[+] Done.')
            except Exception as e:
                print('\t[-]' + str(e))
        else:
            try:
                if args.profile != None:
                    output_filename = 'infornito_profile_{}_{}.csv'.format(str(args.profile[0]),current_time)
                else:
                    output_filename = 'infornito_profiles_{}.csv'.format(current_time)
                
                final_path = os.path.join(args.to[0])
                export_csv(final_path, output_filename, ['url', 'title', 'last_visit', 'count'], history)
                print('\t[+] Done')
            except Exception as e:
                print('\t[-]' + str(e))

    # Print Outputs
    else:
        try:
            for item in history:
                if item.get('last_visit'):
                    print('[{}] {} ( {} )'.format(item['count'], item['url'], item['last_visit']))
                else:
                    print('[{}] {}'.format(item['count'], item['url']))
            print('\n[Total visit] URL ( Last Visit )')
            print('----------------- Summary ----------------')
            print('Total url : {}'.format(len(history)))
        except Exception as e:
            print(e)

def arg_profiles(args):
    print('[~] Profiles :\n')
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

    for profile in browser_profile_list:
        print('\t{} => {} ({})'.format(profile[0],profile[2],profile[1]))
    print('\nUsage : infornito.py history --profile {ProfileID}')

def arg_downloads(args):
    query_filters = parse_filters(args.filter)

    profile_information = profile_info(int(args.profile[0]))
    browser_type = profile_information['browser']
    downloads = browser_modules[browser_type].downloads(profile_information['path'])

    # Filter Output
    if query_filters != None:
        if query_filters.get('ip'):
            if query_filters.get('ip') == True :
                downloads = [item for item in downloads if filterer.ip_equal(item['url'])]
            elif query_filters.get('ip') == 'lan' :
                downloads = [item for item in downloads if filterer.ip_equal(item['url'], 'lan')]
            else:
                downloads = [item for item in downloads if filterer.ip_equal(item['url'], query_filters.get('ip'))]

        if query_filters.get('tld'):
            downloads = [item for item in downloads if filterer.tld_equal(item['url'], query_filters.get('tld'))]

        if query_filters.get('regex'):
            downloads = [item for item in downloads if re.search(query_filters.get('regex'), item['url'])]

        if query_filters.get('domain'):
            downloads = [item for item in downloads if filterer.domain_equal(item['url'], query_filters.get('domain'))]

        if query_filters.get('protocol'):
            downloads = [item for item in downloads if filterer.protocol_equal(item['url'], query_filters.get('protocol'))]

        if query_filters.get('filetype'):
            downloads = [item for item in downloads if filterer.filetype_equal(item['url'], query_filters.get('filetype'))]

        if query_filters.get('port'):
            downloads = [item for item in downloads if filterer.port_equal(item['url'], query_filters.get('port'))]
        
        if query_filters.get('localfile') == True :
            downloads = [item for item in downloads if filterer.is_localfile(item['url'])]

    for item in downloads:
        status = '+'
        if not item['is_fully_download']:
            status = '-'

        print('[{}] {} -> {} ( {} )'.format(status, item['url'], item['saved_in'], item['start_downloading_at']))
    print('\n----------------- Summary ----------------')
    print('[#] Total downloads : {}'.format(len(downloads)))

banner()

parser = argparse.ArgumentParser(description='Browser forensic tool')
parser.add_argument('-v', '--version', action='version', version='[+] infornito current version is {}.'.format(str(__version__)))
subparsers = parser.add_subparsers()

profiles = subparsers.add_parser('profiles', description='List browsers profiles')
profiles.add_argument('--id', nargs=1, help='Select profile id')
profiles.set_defaults(func=arg_profiles)

history = subparsers.add_parser('history')
history.add_argument('--profile', nargs=1, help='select profile id')
history.add_argument('--filter', action='append', help='add filter')
history.add_argument('--urldecode', action='store_true', help='url decode hisotries')
history.add_argument('--export', nargs=1, help='export output to csv file')
history.add_argument('--to', nargs=1, default=['export'], help='destination path for export profile history')
history.set_defaults(func=arg_history)

fingerprint = subparsers.add_parser('fingerprint')
fingerprint.add_argument('--profile', nargs=1, help='Select profile id')
fingerprint.set_defaults(func=arg_fingerprint)

downloads = subparsers.add_parser('downloads')
downloads.add_argument('--profile', nargs=1, help='Select profile id')
downloads.add_argument('--filter', action='append', help='add filter')
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