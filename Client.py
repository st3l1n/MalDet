import argparse
from pyfiglet import Figlet
import requests
import socket
import os
import json
import sys
from pprint import pprint
import base64
import datetime


parser = argparse.ArgumentParser(description='ML-based system for malware detection and behavioural analysis')

parser.add_argument('--version', action='version', version='MalDet v1.0')

subparsers = parser.add_subparsers(help='list of commands')

analysis_parser = subparsers.add_parser('analyze', help='file analysis options')
search_parser = subparsers.add_parser('search', help='search options')
list_parser = subparsers.add_parser('list_files', help='all files analyzed')

analysis_parser.add_argument('ip', metavar='ip', action='store',
                             type=str, help='ip address of analysis server')
analysis_parser.add_argument('file', metavar='filepath',
                             type=str, help='choose path to file for analysis', default='')
analysis_parser.add_argument('--dir', dest='is_dir', action='store_true',
                             default=False, help='is a chosen path a directory or a file')
analysis_parser.add_argument('--mode', dest='mode', metavar='mode', action='store', default=1,
                             type=int, help='mode of analysis: 0 - simple ML analysis'
                                            ' returning [filename: type];'
                                            ' 1 - full analysis report;'
                                            ' 2 - sandbox analysis;')

search_parser.add_argument('ip', metavar='ip', action='store',
                           type=str, help='ip address of analysis server')

search_parser.add_argument('--search_mode', dest='search_mode',
                           metavar='search_mode', action='store',
                           default='h', help='h - for hash search in sha512 format;'
                                             ' i - for client ip search in common format;'
                                             ' d - for date search in format dd/mm/yyyy')
search_parser.add_argument('--search_arg', dest='search_arg', metavar='search_arg',
                           action='store', help='value of item for search'
                                                ' depends on search_mode')
search_parser.add_argument('--mode', dest='mode', metavar='mode', action='store', default=1,
                             type=int, help='mode of analysis: 0 - simple ML analysis'
                                            ' returning [filename: type];'
                                            ' 1 - full analysis report;'
                                            ' 2 - sandbox analysis;')

list_parser.add_argument('ip', metavar='ip', action='store',
                         type=str, help='ip address of analysis server')





def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP


headers = {'IP': get_ip(), 'MFL': 'False', 'date': '', 'search_ip': '', 'cookie': '', 'dynamic_search': ''}


def check_request(address: str):
    try:
        response = requests.get(f'{address}/', headers=headers)
    except Exception as e:
        print(e)
        return False
    cookie = json.loads(response.content)
    ip = base64.decodebytes(cookie.encode()).decode().split(' ')[0]
    if ip == headers['IP']:
        headers['cookie'] = cookie
        return True
    else:
        return False


def send_file_to_analysis(address: str, filename: str, mode=1):
    print('Uploading...', end='')
    with open(filename, "rb") as fd:
        data = fd.read()
    if '/' in filename:
        filename = filename.split('/')[-1]
    if mode == 2:
        print('you can make some coffee now =)')
        print("""
        
                          )     (
                   ___...(-------)-....___
               .-""       )    (          ""-.
         .-'``'|-._             )         _.-|
        /  .--.|   `""---...........---""`   |
       /  /    |                             |
       |  |    |                             |
        \  \   |                             |
         `\ `\ |                             |
           `\ `|                             |
           _/ /\                             /
          (__/  \                           /
       _..---**` \                         /`**---.._
    .-'           \                       /          '-.
   :               `-.__             __.-'              :
   :                  ) ""---...---"" (                 :
    '._               `"--...___...--"`              _.'
      **--..__                              __..--***
       '._     ***----.....______.....----***     _.'
          `""--..,,_____            _____,,..--""`
                        `***----***
       """)
    response = requests.post(
        f'{address}/files/{filename}/{mode}', data=data, headers=headers)
    print('done!')
    if mode == 2:
        if os.path.exists('report_%s.zip' % filename):
            report_name = 'report_%s%s.zip' % (filename, datetime.datetime.now().strftime("%d-%m-%Y_%H:%M"))
        else:
            report_name = 'report_%s.zip' % filename
        with open(report_name, 'wb') as f:
            f.write(response.content)
        return "Report is saved in current directory"   
    else:
##        with open('tmp.json', 'w') as f:
##            f.write(response.text)
        return json.loads(response.text)


def send_many_files(address: str, path: str, mode=1):
    MODE = 3
    headers['MFL'] = 'True'
    all_in_one = os.walk(path)
    files = []
    for a in all_in_one:
        for f in a[2]:
            files.append(os.path.join(a[0], f))
    for file in files:
        pprint(send_file_to_analysis(address, file, mode=MODE))
    response = requests.get(f'{address}/files/analysis/{mode}',
                            headers=headers)
    if mode == 2:
        if os.path.exists('all_report.zip'):
            report_name = 'all_report_%s.zip' % datetime.datetime.now().strftime("%d-%m-%Y_%H:%M")
        else:
            report_name = 'all_report.zip'
        with open(report_name, 'wb') as f:
            f.write(response.content)
        return "All reports were saved in current directory"
    else:
        return json.loads(response.text)


def search_file(address: str, h='123321', mode='hash', ip='', date='', dynamic=False):
    if dynamic:
        headers['dynamic_search'] = 'True'
        response = requests.get(
        f'{address}/search/{h}', headers=headers)
        try:
            msg = json.loads(response.content)
            return msg
        except Exception as e:
            filename = 'result.zip'
            if os.path.exists(filename):
                filename = 'result_%s.zip' % datetime.datetime.now().strftime("%d-%m-%Y_%H:%M")
            with open(filename, 'wb') as f:
                f.write(response.content)
            return 'Report was saved in current dir'
    if mode == 'ip':
        headers['search_ip'] = ip
    elif mode == 'date':
        headers['date'] = date
    response = requests.get(
        f'{address}/search/{h}', headers=headers)
    return json.loads(response.text)


def list_files(address: str):
    response = requests.get(
        f'{address}/files', headers=headers)
    data = response.text
    return json.loads(data)


def analyze(args: argparse.Namespace, server_address: str, parser: argparse.ArgumentParser):
    if not check_request(server_address):
        print('Wrong server address')
        return
    filepath = args.file
    #server_address = 'http://' + args.ip + ':8003'
    analysis_mode = args.mode
    try:
        if args.is_dir:
            report = send_many_files(address=server_address, path=filepath, mode=analysis_mode)
        else:
            report = send_file_to_analysis(address=server_address, filename=filepath, mode=analysis_mode)
    except Exception as e:
        print(e)
        print('invalid arguments, check usage page')
        parser.print_help()
        return
    return report


def search(args: argparse.Namespace, server_address: str, parser: argparse.ArgumentParser):
    if not check_request(server_address):
        print('Wrong server address')
        return
    search_mode = args.search_mode
    search_arg = args.search_arg
    if args.mode:
        mode = args.mode
        if mode == 2:
            result = search_file(address=server_address, h=search_arg, mode='hash', dynamic=True)
            print(result)
            return
    if search_mode == 'h':
        report = search_file(address=server_address, h=search_arg, mode='hash')
    elif search_mode == 'i':
        report = search_file(address=server_address, mode='ip', ip=search_arg)
    elif search_mode == 'd':
        report = search_file(address=server_address, mode='date', date=search_arg)
    else:
        print('invalid arguments, check usage page')
        parser.print_help()
        return
    pprint(report)


def get_list_files(server_address: str):
    if not check_request(server_address):
        print('Wrong server address')
        return
    report = list_files(address=server_address)
    return report



f = Figlet(font='starwars')
print(f.renderText('MalDet'))
t1 = datetime.datetime.now()
if len(sys.argv) > 1:
    main_mode = sys.argv[1]
    args = parser.parse_args()
else:
    print(parser.print_usage())
    sys.exit()
server_address = 'http://' + args.ip + ':8003'
if main_mode == 'analyze':
    pprint(analyze(args, server_address, parser))
elif main_mode == 'search':
    search(args, server_address, parser)
elif main_mode == 'list_files':
    pprint(get_list_files(server_address))
else:
    parser.print_usage()
t2 = datetime.datetime.now()
print("[+] Working time: "+str(t2-t1))




