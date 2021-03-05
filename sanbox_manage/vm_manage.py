import subprocess
import time
import sys
import shutil
import os
import ssdeep
import pefile

CWD = '/home/cuckoo/PycharmProjects/vm_manage/'
SANDBOX_PATH = '/home/cuckoo/vmware/MDB/MDB.vmx'
SCREENS_PATH = f'{CWD}screens/'
if sys.argv[1] and os.path.exists(sys.argv[1]):
    MALWARE = sys.argv[1]
    MALWARE_NAME = sys.argv[1].split('/')[-1]
else:
    print('Wrong file param')
    sys.exit()
if MALWARE_NAME[-4:] != '.exe':
    MALWARE_NAME += '.exe'
print(f'[+] Malware name is {MALWARE_NAME}')
SANDBOX_MALWARE_PATH = 'C:\\Users\\MalDet\\Desktop\\Malware\\' + MALWARE_NAME
CLEAR_SNAPSHOT_NAME = 'clean_state'
SANDBOX_USERNAME = 'MalDet'
SANDBOX_PASSWORD = 'MalDet'
DELAY = 20
with open('/home/cuckoo/vmware/MDB/sandbox.conf', 'r+') as f:
    SNAPSHOT_NUMBER = int(f.read()) + 1
    f.seek(0)
    f.write(str(SNAPSHOT_NUMBER))
INFECTED_VMEM_NAME = 'MDB-Snapshot%d.vmem' % SNAPSHOT_NUMBER
INFECTED_SNAPSHOT_NAME = 'Infected_%s' % MALWARE_NAME


def capturing(mal_name: str):
    for i in range(12):
        name = mal_name + '_%d' % i
        subprocess.run(
            f'vmrun -gu {SANDBOX_USERNAME} -gp {SANDBOX_PASSWORD} captureScreen '
            f'{SANDBOX_PATH} {SCREENS_PATH+name}'.split(' '), stdout=subprocess.PIPE)
        time.sleep(DELAY / 4)
    print('screens done in %s' % SCREENS_PATH)


def hash_calc(malware_path=MALWARE):
    pe = pefile.PE(malware_path)
    imp_hash = pe.get_imphash()
    ssdeep_hash = ssdeep.hash_from_file(malware_path)
    return imp_hash, ssdeep_hash

def memory_capturing():
    print('[+] Starting the sandbox')
    cmd1 = subprocess.run(f'vmrun -T ws start {SANDBOX_PATH}'.split(' '), stdout=subprocess.PIPE)
    print('[+] The sandbox has started')
    print()
    print('[+] Transferring the file...')
    cmd2 = subprocess.run(f'vmrun -gu {SANDBOX_USERNAME} -gp {SANDBOX_PASSWORD} copyFileFromHostToGuest {SANDBOX_PATH} '
                          f'{MALWARE} {SANDBOX_MALWARE_PATH}'.split(' '), stdout=subprocess.PIPE)
    print('[+] The file has transferred')
    print()
    print('[+] Executing the file...')
    cmd3 = subprocess.run(f'vmrun -gu {SANDBOX_USERNAME} -gp {SANDBOX_PASSWORD} runProgramInGuest {SANDBOX_PATH} '
                          f'-interactive -noWait '
                          f'{SANDBOX_MALWARE_PATH}'.split(' '), stdout=subprocess.PIPE)
    print('[+] The file has executed')
    print()
    print('[+] Capturing the sandbox state...')
    capturing(MALWARE_NAME)
    print('[+] The screenshots have captured')
    print()
    print('[+] Making infected memory snapshot...')
    cmd4 = subprocess.run(f'vmrun -gu {SANDBOX_USERNAME} -gp {SANDBOX_PASSWORD} snapshot {SANDBOX_PATH} '
                          f'{INFECTED_SNAPSHOT_NAME}'.split(' '), stdout=subprocess.PIPE)
    print('[+] Infected memory snapshot has created')
    print()
    print('[+] Copying infected memory snapshot to analyzer directory...')
    shutil.copy(f'/home/cuckoo/vmware/MDB/{INFECTED_VMEM_NAME}',
                f'{CWD}Infected_dumps/{INFECTED_SNAPSHOT_NAME}.vmem')
    print('[+] Infected memory snapshot has copied')
    print()
    # time.sleep(DELAY)
    print('[+] Reverting the sandbox to clean state...')
    cmd5 = subprocess.run(f'vmrun -T ws revertToSnapshot {SANDBOX_PATH} '
                          f'{CLEAR_SNAPSHOT_NAME}'.split(' '), stdout=subprocess.PIPE)
    time.sleep(DELAY / 2)
    print('[+] The sandbox has reverted')
    print()
    print('[+] Deleting infected snapshot...')
    cmd6 = subprocess.run(f'vmrun -T ws deleteSnapshot {SANDBOX_PATH} '
                          f'{INFECTED_SNAPSHOT_NAME}'.split(' '), stdout=subprocess.PIPE)
    print('[+] Infected snapshot has deleted')
    time.sleep(DELAY / 2)
    infected_snapshot_path = f'{CWD}Infected_dumps/{INFECTED_SNAPSHOT_NAME}.vmem'
    cmd7 = subprocess.run(f'vmrun -T ws suspend {SANDBOX_PATH} soft'.split(' '), stdout=subprocess.PIPE)
    print('[+] The sandbox suspended')
    return infected_snapshot_path


hashes = hash_calc(MALWARE)
with open('hashes.txt', 'w+') as f:
    print(f'{MALWARE_NAME} imphash: {hashes[0]}', f'{MALWARE_NAME} ssdeep hash: {hashes[1]}', sep='\t', end='\n', file=f)
inf_snap = memory_capturing()
clean_snap = f'{CWD}clean_state.vmem'
PROFILE = 'Win7SP1x64_24000'
VOLDIFF_PATH = f'{CWD}VolDiff/VolDiff-master/VolDiff.py'
subprocess.run(['python2', VOLDIFF_PATH, clean_snap, inf_snap, PROFILE, '--malware-checks'])



