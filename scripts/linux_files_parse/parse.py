import os
HEADER = b'\x7fELF'
files_tree = os.walk('D:\AFSO\diploma\current_version\practice\linux_utils\linux_utils')
file_path = list()
sample_files = list()
for address, dirs, files in files_tree:
    for file in files:
        file_path.append(address+'/'+file)
for file in file_path:
    with open(file, 'rb') as f:
        header = f.read(4)
    if header == HEADER:
        sample_files.append(file+'\n')
with open('linux_sample_linux_utils.txt', 'wt') as f:
    f.writelines(sample_files)
