from hashlib import md5
import os

dll_list = os.listdir('../dlls')
hash_table = dict()
for dll in dll_list:
    with open('../dlls/'+dll, 'rb') as f:
        hash_table[dll.split('.')[0]] = str(md5(f.read()).hexdigest())


def append_hash(path_to_dll, path_to_hash_table):
    with open(path_to_dll, 'rb') as f:
        key, value = path_to_dll.split('/')[-1].split('.')[0], str(md5(f.read()).hexdigest())
    with open(path_to_hash_table, 'at') as f:
        f.write(key + ' : ' + value + '\n')


def verify_hash(hash, path_to_hash_table):
    with open(path_to_hash_table, 'rt') as f:
        data = f.read()
    if hash in data:
        return True
    else:
        return False
