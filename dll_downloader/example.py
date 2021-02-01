import subprocess
import os
from time import sleep

with open('example.txt', 'wt') as f:
    f.write(str(os.getpid()))

print('Я запустилсЯ')
print(os.getpid())
sleep(5)
subprocess.Popen('py -3 rerun.py')
