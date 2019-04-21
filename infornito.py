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
import platform
import re
import urllib.parse
from shutil import copyfile
from datetime import datetime
from browsers.firefox import firefox
from browsers.chrome import chrome
from browsers.safari import safari
from libs.exporter import export_csv


def banner():
    print('''
  _______     __       _____     __          
 / ___/ /__  / /  ___ / ___/_ __/ /  ___ ____
/ (_ / / _ \/ _ \/ -_) /__/ // / _ \/ -_) __/
\___/_/\___/_.__/\__/\___/\_, /_.__/\__/_/   
                         /___/               
            < Infornito v1.1 >
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

def get_history(profile_id):
    profile_information = profile_info(profile_id)
    history = browser_modules[profile_information['browser']].history(profile_information['path'])
    return history

def arg_history(args):

    history = []
    if args.profile == None:
        print('[~] Getting profiles history ...')
        profiles = profile_info()
        for profile_id in range(1,len(profiles)+1):
            history_response = get_history(profile_id)
            if not history_response['status']:
                print('[-] Profile #{} : {}'.format(profile_id, history_response['data']))
            else:
                history += history_response['data']
    else:
        history_response = get_history(str(args.profile[0]))
        if not history_response['status']:
            print('[-] {}'.format(history_response['data']))
            exit()
        
        history = history_response['data']

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

        if query_filters.get('domain'):
            history = [item for item in history if re.search(r'^(https?:\/\/)?(.*\.)?('+query_filters.get('domain').replace(',','|')+')(:\d{1,5})?(\/.*)?$', item['url'])]

        if query_filters.get('protocol'):
            history = [item for item in history if re.search(r'^'+query_filters.get('protocol')+':\/\/.*', item['url'])]
    
        if query_filters.get('filetype'):
            history = [item for item in history if re.search(r'^https?:\/\/.*\/.*\.('+query_filters.get('filetype').replace(',','|')+')$', item['url'])]

        if query_filters.get('port'):
            history = [item for item in history if re.search(r'^https?:\/\/.*:('+query_filters.get('port').replace(',','|')+')\/.*.$', item['url'])]

        if query_filters.get('wordpress') == True :
            history = [item for item in history if re.search(r'(wp-login\.php|\/wp-content\/|\/wp-admin)', item['url'])]

        if query_filters.get('adminpanels') == True :
            history = [item for item in history if re.search(r'(\/admin\/|\/administrator\/|\/wp-admin)', item['url'])]

        if query_filters.get('xss') == True :
            history = [item for item in history if re.search(r'''<[^\w<>]*(?:[^<>"'\s]*:)?[^\w<>]*(?:\W*s\W*c\W*r\W*i\W*p\W*t|\W*f\W*o\W*r\W*m|\W*s\W*t\W*y\W*l\W*e|\W*s\W*v\W*g|\W*m\W*a\W*r\W*q\W*u\W*e\W*e|(?:\W*l\W*i\W*n\W*k|\W*o\W*b\W*j\W*e\W*c\W*t|\W*e\W*m\W*b\W*e\W*d|\W*a\W*p\W*p\W*l\W*e\W*t|\W*p\W*a\W*r\W*a\W*m|\W*i?\W*f\W*r\W*a\W*m\W*e|\W*b\W*a\W*s\W*e|\W*b\W*o\W*d\W*y|\W*m\W*e\W*t\W*a|\W*i\W*m\W*a?\W*g\W*e?|\W*v\W*i\W*d\W*e\W*o|\W*a\W*u\W*d\W*i\W*o|\W*b\W*i\W*n\W*d\W*i\W*n\W*g\W*s|\W*s\W*e\W*t|\W*i\W*s\W*i\W*n\W*d\W*e\W*x|\W*a\W*n\W*i\W*m\W*a\W*t\W*e)[^>\w])|(?:<\w[\s\S]*[\s\0\/]|['"])(?:formaction|style|background|src|lowsrc|ping|on(?:d(?:e(?:vice(?:(?:orienta|mo)tion|proximity|found|light)|livery(?:success|error)|activate)|r(?:ag(?:e(?:n(?:ter|d)|xit)|(?:gestur|leav)e|start|drop|over)?|op)|i(?:s(?:c(?:hargingtimechange|onnect(?:ing|ed))|abled)|aling)|ata(?:setc(?:omplete|hanged)|(?:availabl|chang)e|error)|urationchange|ownloading|blclick)|Moz(?:M(?:agnifyGesture(?:Update|Start)?|ouse(?:PixelScroll|Hittest))|S(?:wipeGesture(?:Update|Start|End)?|crolledAreaChanged)|(?:(?:Press)?TapGestur|BeforeResiz)e|EdgeUI(?:C(?:omplet|ancel)|Start)ed|RotateGesture(?:Update|Start)?|A(?:udioAvailable|fterPaint))|c(?:o(?:m(?:p(?:osition(?:update|start|end)|lete)|mand(?:update)?)|n(?:t(?:rolselect|extmenu)|nect(?:ing|ed))|py)|a(?:(?:llschang|ch)ed|nplay(?:through)?|rdstatechange)|h(?:(?:arging(?:time)?ch)?ange|ecking)|(?:fstate|ell)change|u(?:echange|t)|l(?:ick|ose))|m(?:o(?:z(?:pointerlock(?:change|error)|(?:orientation|time)change|fullscreen(?:change|error)|network(?:down|up)load)|use(?:(?:lea|mo)ve|o(?:ver|ut)|enter|wheel|down|up)|ve(?:start|end)?)|essage|ark)|s(?:t(?:a(?:t(?:uschanged|echange)|lled|rt)|k(?:sessione|comma)nd|op)|e(?:ek(?:complete|ing|ed)|(?:lec(?:tstar)?)?t|n(?:ding|t))|u(?:ccess|spend|bmit)|peech(?:start|end)|ound(?:start|end)|croll|how)|b(?:e(?:for(?:e(?:(?:scriptexecu|activa)te|u(?:nload|pdate)|p(?:aste|rint)|c(?:opy|ut)|editfocus)|deactivate)|gin(?:Event)?)|oun(?:dary|ce)|l(?:ocked|ur)|roadcast|usy)|a(?:n(?:imation(?:iteration|start|end)|tennastatechange)|fter(?:(?:scriptexecu|upda)te|print)|udio(?:process|start|end)|d(?:apteradded|dtrack)|ctivate|lerting|bort)|DOM(?:Node(?:Inserted(?:IntoDocument)?|Removed(?:FromDocument)?)|(?:CharacterData|Subtree)Modified|A(?:ttrModified|ctivate)|Focus(?:Out|In)|MouseScroll)|r(?:e(?:s(?:u(?:m(?:ing|e)|lt)|ize|et)|adystatechange|pea(?:tEven)?t|movetrack|trieving|ceived)|ow(?:s(?:inserted|delete)|e(?:nter|xit))|atechange)|p(?:op(?:up(?:hid(?:den|ing)|show(?:ing|n))|state)|a(?:ge(?:hide|show)|(?:st|us)e|int)|ro(?:pertychange|gress)|lay(?:ing)?)|t(?:ouch(?:(?:lea|mo)ve|en(?:ter|d)|cancel|start)|ime(?:update|out)|ransitionend|ext)|u(?:s(?:erproximity|sdreceived)|p(?:gradeneeded|dateready)|n(?:derflow|load))|f(?:o(?:rm(?:change|input)|cus(?:out|in)?)|i(?:lterchange|nish)|ailed)|l(?:o(?:ad(?:e(?:d(?:meta)?data|nd)|start)?|secapture)|evelchange|y)|g(?:amepad(?:(?:dis)?connected|button(?:down|up)|axismove)|et)|e(?:n(?:d(?:Event|ed)?|abled|ter)|rror(?:update)?|mptied|xit)|i(?:cc(?:cardlockerror|infochange)|n(?:coming|valid|put))|o(?:(?:(?:ff|n)lin|bsolet)e|verflow(?:changed)?|pen)|SVG(?:(?:Unl|L)oad|Resize|Scroll|Abort|Error|Zoom)|h(?:e(?:adphoneschange|l[dp])|ashchange|olding)|v(?:o(?:lum|ic)e|ersion)change|w(?:a(?:it|rn)ing|heel)|key(?:press|down|up)|(?:AppComman|Loa)d|no(?:update|match)|Request|zoom))[\s\0]*=''', item['url'], re.IGNORECASE)]

        if query_filters.get('sqli') == True :
            history = [item for item in history if re.search(r'''(?:(union(.*)select(.*)from))|(?:[\s()]case\s*\()|(?:\)\s*like\s*\()|(?:having\s*[^\s]+\s*[^\w\s])|(?:if\s?\([\d\w]\s*[=<>~])|(?:\"\s*or\s*\"?\d)|(?:\\x(?:23|27|3d))|(?:^.?\"$)|(?:(?:^[\"\\]*(?:[\d\"]+|[^\"]+\"))+\s*(?:n?and|x?or|not|\|\||\&\&)\s*[\w\"[+&!@(),.-])|(?:[^\w\s]\w+\s*[|-]\s*\"\s*\w)|(?:@\w+\s+(and|or)\s*[\"\d]+)|(?:@[\w-]+\s(and|or)\s*[^\w\s])|(?:[^\w\s:]\s*\d\W+[^\w\s]\s*\".)|(?:\Winformation_schema|table_name\W)|(?:\"\s*\*.+(?:or|id)\W*\"\d)|(?:\^\")|(?:^[\w\s\"-]+(?<=and\s)(?<=or\s)(?<=xor\s)(?<=nand\s)(?<=not\s)(?<=\|\|)(?<=\&\&)\w+\()|(?:\"\s*[^\w\s]+\s*[\W\d].*(?:#|--))|(?:\".*\*\s*\d)|(?:\"\s*or\s[^\d]+[\w-]+.*\d)|(?:[\d\W]\s+as\s*[\"\w]+\s*from)|(?:^[\W\d]+\s*(?:union|select|create|rename|truncate|load|alter|delete|update|insert|desc))|(?:(?:select|create|rename|truncate|load|alter|delete|update|insert|desc)\s+(?:(?:group_)concat|char|load_file)\s?\(?)|(?:end\s*\);)|(\"\s+regexp\W)|(?:[\s(]load_file\s*\()|(?:@.+=\s*\(\s*select)|(?:\d+\s*or\s*\d+\s*[\-+])|(?:\/\w+;?\s+(?:having|and|or|select)\W)|(?:\d\s+group\s+by.+\()|(?:(?:;|#|--)\s*(?:drop|alter))|(?:(?:;|#|--)\s*(?:update|insert)\s*\w{2,})|(?:[^\w]SET\s*@\w+)|(?:(?:n?and|x?or|not |\|\||\&\&)[\s(]+\w+[\s)]*[!=+]+[\s\d]*[\"=()])|(?:\"\s+and\s*=\W)|(?:\(\s*select\s*\w+\s*\()|(?:\*\/from)|(?:\+\s*\d+\s*\+\s*@)|(?:\w\"\s*(?:[-+=|@]+\s*)+[\d(])|(?:coalesce\s*\(|@@\w+\s*[^\w\s])|(?:\W!+\"\w)|(?:\";\s*(?:if|while|begin))|(?:\"[\s\d]+=\s*\d)|(?:order\s+by\s+if\w*\s*\()|(?:[\s(]+case\d*\W.+[tw]hen[\s(])''', item['url'], re.IGNORECASE)]
        
        if query_filters.get('lfi') == True :
            history = [item for item in history if re.search(r'''(?:etc\/\W*passwd)|(?:(?:\/|\\)?\.\.+(\/|\\)(?:\.+)?)''', item['url'], re.IGNORECASE)]

    if args.export != None:
        print('[~] Exporting histories to csv file ...')
        try:
            current_time = datetime.utcnow().strftime('%Y-%m-%d %H-%M-%S')
            if args.profile != None:
                output_filename = 'infornito_profile_{}_{}.csv'.format(str(args.profile[0]),current_time)
            else:
                output_filename = 'infornito_profiles_{}.csv'.format(current_time)
            
            final_path = os.path.join(args.to[0], 'history')
            export_csv(final_path, output_filename, ['url', 'last_visit', 'count'], history)
            print('[+] Done')
        except Exception as e:
            print('[-]' + str(e))
        
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

parser = argparse.ArgumentParser(description='Browser forensic tool')
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