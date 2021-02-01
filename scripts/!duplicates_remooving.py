import os
#
# with open('duplicates.txt', 'rt') as f:
#     data = f.readlines()
# removing_data = [d.split(' and ')[0].split(': ')[1] for d in data]
# for file in removing_data:
#     try:
#         os.remove(file.strip())
#     except FileNotFoundError:
#         pass

remove_list = ['/root/malware_volume/APT/Dictionaries/Icon\n','/root/malware_volume/APT/Aborted Attacks/Icon\n', '/root/malware_volume/APT/Bookmarks/Icon\n', '/root/malware_volume/APT/FAQ : Doc/Icon\n', '/root/malware_volume/APT/Logs/Icon\n', '']
os.remove()
