from bs4 import BeautifulSoup
import requests
from hash_gen import append_hash, verify_hash, md5
import os
# import subprocess
from threading import Timer, Lock
import win32api
import re


with open('conf.cfg', 'wt') as f:
    f.write(str(os.getpid()))


def exxit():
    PROCESS_TERMINATE = 1
    with open('conf.cfg', 'rt') as f:
        pid = int(f.read())
    handle = win32api.OpenProcess(PROCESS_TERMINATE, False, pid)
    print("process terminated")
    # CREATE_NEW_PROCESS_GROUP = 0x00000200
    # DETACHED_PROCESS = 0x00000008
    # subprocess.Popen('restart.bat', stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    #           creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
    win32api.TerminateProcess(handle, -1)
    win32api.CloseHandle(handle)


class TimerEx(object):
    """
    A reusable thread safe timer implementation
    """

    def __init__(self, interval_sec, function, *args, **kwargs):
        """
        Create a timer object which can be restarted

        :param interval_sec: The timer interval in seconds
        :param function: The user function timer should call once elapsed
        :param args: The user function arguments array (optional)
        :param kwargs: The user function named arguments (optional)
        """
        self._interval_sec = interval_sec
        self._function = function
        self._args = args
        self._kwargs = kwargs
        # Locking is needed since the '_timer' object might be replaced in a different thread
        self._timer_lock = Lock()
        self._timer = None

    def start(self, restart_if_alive=True):
        """
        Starts the timer and returns this object [e.g. my_timer = TimerEx(10, my_func).start()]

        :param restart_if_alive: 'True' to start a new timer if current one is still alive
        :return: This timer object (i.e. self)
        """
        with self._timer_lock:
            # Current timer still running
            if self._timer is not None:
                if not restart_if_alive:
                    # Keep the current timer
                    return self
                # Cancel the current timer
                self._timer.cancel()
            # Create new timer
            self._timer = Timer(self._interval_sec, self.__internal_call)
            self._timer.start()
        # Return this object to allow single line timer start
        return self

    def cancel(self):
        """
        Cancels the current timer if alive
        """
        with self._timer_lock:
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None

    def is_alive(self):
        """
        :return: True if current timer is alive (i.e not elapsed yet)
        """
        with self._timer_lock:
            if self._timer is not None:
                return self._timer.is_alive()
        return False

    def __internal_call(self):
        # Release timer object
        with self._timer_lock:
            self._timer = None
        # Call the user defined function
        self._function(*self._args, **self._kwargs)


def dll_download(link, num, begin=1, span_number=1):
    for i in range(begin, num):
        if i == 1:
            soup = BeautifulSoup(requests.get(link).content, features='html.parser')
        else:
            soup = BeautifulSoup(requests.get(link+'/'+str(i)).content, features='html.parser')
        spans = soup.find_all('span')
        span_numbers = range(1,47)
        pat = re.compile(' [0-9]+ ')
        dwnld_links = []
        for span in spans:
            if re.findall(pat, str(span)):
                dwnld_links.append(span.parent.parent.find('a')['href'])
        dwnld_urls = dict()
        for lll, span_num in zip(dwnld_links, span_numbers):
            dwnld_urls[lll] = span_num
        t = TimerEx(300, exxit)
        if i == begin:
            tmp = span_number
        else:
            tmp = 1
        for url, span in dwnld_urls.items():
            if tmp > span:
                print('%s has already downloaded' % url)
                continue
            try:
                t.start()
                new_soup = BeautifulSoup(requests.get(url).content, features='html.parser')
                new_links = [l for l in new_soup.find_all('a') if 'onclick' in l.attrs.keys()]
                if new_links[0]['href'] == 'javascript:void(0);':
                    continue
                ss = BeautifulSoup(requests.get(new_links[0]['href']).content, features='html.parser')
                ll = [l['href'] for l in ss.find_all('a') if 'title' in l.attrs.keys() and 'try again' in l['title']]
                r = requests.get(ll[0])
                if verify_hash(str(md5(r.content).hexdigest()), 'hash_table.txt'):
                    print(ll[0] + ' has already downloaded')
                    continue
                print(ll[0])
                with open('../dlls/'+ll[0].split('/')[3]+'.zip', 'wb') as f:
                    f.write(r.content)
                append_hash('../dlls/'+ll[0].split('/')[3]+'.zip', 'hash_table.txt')
                with open('info.txt', 'wt') as f:
                    f.write(link + ' number of page is %d %d' % (i, span))
                t.cancel()
            except Exception as e:
                print(e)
                exit(0)


base_url = 'http://www.dlldownloader.com/'
alphabet = [chr(98+i) for i in range(0, 25)]
relevant_links = [base_url+letter for letter in alphabet ]
number_of_pages = [9, 39, 27, 14, 14, 11, 14, 26, 9, 7, 21, 38, 16, 9, 28, 4, 12, 18, 9, 5, 7, 8, 3, 2, 2]
dwnldr = dict()
for link, num in zip(relevant_links, number_of_pages):
    dwnldr[link] = num
with open('info.txt', 'r') as f:
    data = f.read().split(' ')
span = int(data[-1])
start_link = data[0]
start = int(data[-2])
for key in dwnldr.copy().keys():
    if key == start_link:
        break
    del dwnldr[key]
for link, num, j in zip(dwnldr.keys(), dwnldr.values(), range(len(dwnldr.keys()))):
    if j == 0:
        dll_download(link, num, start, span)
    else:
        dll_download(link, num)

