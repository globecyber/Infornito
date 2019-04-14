#!/usr/bin/env python3
import argparse
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
            < Infornito v0.2 >
''')

browser_modules = {
    'firefox': firefox(), 
    'chrome': chrome(), 
    'safari': safari()
}

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
            extract_filter = filter_item.split('=')
            filters[extract_filter[0]] = extract_filter[1]
        
        return filters
    return None

def arg_fingerprint(args):
    
    profile_information = profile_info(int(args.profile[0]))
    browser_type = profile_information['browser']

    print('Profile path : {}\n'.format(profile_information['path']))
    fingerprint_files = browser_modules[browser_type].fingerprint(profile_information['path'])
    for filename, fingerprints in fingerprint_files.items():
        print('[+] ' + filename)
        for algorithm, fingerprint in fingerprints.items():
            print('\t{} : {}'.format(algorithm, fingerprint))

def arg_history(args):
    profile_information = profile_info(int(args.pid[0]))
    browser_type = profile_information['browser']
    history = browser_modules[browser_type].history(profile_information['path'], filters=parse_filters(args.filter))
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
    profile_information = profile_info(int(args.pid[0]))
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
history.add_argument('--pid', nargs=1, help='Select profile id')
history.add_argument('--filter', action='append', help='add filter')
history.set_defaults(func=arg_history)

fingerprint = subparsers.add_parser('fingerprint')
fingerprint.add_argument('--profile', nargs=1, help='Select profile id')
fingerprint.set_defaults(func=arg_fingerprint)

downloads = subparsers.add_parser('downloads')
downloads.add_argument('--pid', nargs=1, help='Select profile id')
downloads.set_defaults(func=arg_downloads)

args = parser.parse_args()
try:
    args.func(args)
except AttributeError:
    parser.error("too few arguments")