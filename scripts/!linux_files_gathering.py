import os

def unique_name_generator(path):
    if os.path.exists(path):
        new_path = path + '_1'
    else:
        new_path = path
    return new_path

path_1 = 'D:\AFSO\diploma\current_version\practice\linux_files_parse/linux_sample_lib_utils.txt'
path_2 = 'D:\AFSO\diploma\current_version\practice\linux_files_parse/linux_sample_lib32_utils.txt'
path_3 = 'D:\AFSO\diploma\current_version\practice\linux_files_parse/linux_sample_lib32x_utils.txt'
path_4 = 'D:\AFSO\diploma\current_version\practice\linux_files_parse/linux_sample_linux_utils.txt'
for path in [path_1, path_2, path_3, path_4]:
    with open(path, 'rt') as f:
        files = f.readlines()
    print(len(files))
    files_read = 0
    files_wrote = 0
    for fi in files:
        with open(fi.strip(), 'rb') as f:
            data = f.read()
            files_read += 1
        name = unique_name_generator('D:/AFSO/diploma/current_version/practice/all_linux_files/files/'+fi.split('/')[-1].strip())
        with open(name, 'wb') as f:
            f.write(data)
            files_wrote += 1
    print('files_read %d' % files_read)
    print('files_wrote %d' % files_wrote)
