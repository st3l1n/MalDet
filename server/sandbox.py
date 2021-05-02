import subprocess
import time
import sys
import shutil
import os
import ssdeep
import pefile
import datetime
from hashlib import sha1
from distutils.dir_util import copy_tree
import re
from set import *


if sys.argv[1] and os.path.exists(sys.argv[1]):
    MALWARE = sys.argv[1]
    MALWARE_NAME = sys.argv[1].split('/')[-1]
    if len(sys.argv) > 2:
        if sys.argv[2] == 'save_dump':
            SAVE_DUMP_FLAG = True
        else:
            print('Wrong options params')
            sys.exit()
else:
    print('Wrong file param')
    sys.exit()
if MALWARE_NAME[-4:] != '.exe':
    MALWARE_NAME += '.exe'
print(f'[+] Malware name is {MALWARE_NAME}')


REPORT_PATH = f"{REPORT_PATH}VolDiff_Report_{MALWARE_NAME.split('.')[0]}.txt"
if os.path.exists(f'{CWD}screens/{MALWARE_NAME}'):
    os.mkdir(f'{CWD}screens/{MALWARE_NAME}_%s' % datetime.datetime.now().strftime("%d-%m-%Y_%H:%M"))
    SCREENS_PATH = f'{CWD}screens/{MALWARE_NAME}_%s/' % datetime.datetime.now().strftime("%d-%m-%Y_%H:%M")
else:
    os.mkdir(f'{CWD}screens/{MALWARE_NAME}')
    SCREENS_PATH = f'{CWD}screens/{MALWARE_NAME}/'
SANDBOX_MALWARE_PATH = SANDBOX_MALWARE_PATH + MALWARE_NAME
with open(SANDBOX_CONF, 'r+') as f:
    SNAPSHOT_NUMBER = int(f.read()) + 1
    f.seek(0)
    f.write(str(SNAPSHOT_NUMBER))

INFECTED_VMEM_NAME = 'MDB-Snapshot%d.vmem' % SNAPSHOT_NUMBER
INFECTED_SNAPSHOT_NAME = 'Infected_%s' % MALWARE_NAME


def capturing(mal_name: str):
    for i in range(12):
        name = mal_name + '_%d' % i + '.png'
        subprocess.run(
            f'vmrun -gu {SANDBOX_USERNAME} -gp {SANDBOX_PASSWORD} captureScreen '
            f'{SANDBOX_PATH} {SCREENS_PATH+name}'.split(' '), stdout=subprocess.PIPE)
        time.sleep(DELAY / 4)
    # print('screens done in %s' % SCREENS_PATH)

def child_search(target_process_pid, psscan_output):
    target_child_processes = []
    ppids = []
    for entry in psscan_output[4:-3]:
        entry = entry.split()
        if entry[3] == target_process_pid:
            target_child_processes.append(entry[2])
        ppids.append(entry[3])
    for pid in target_child_processes:
        if pid in ppids:
            childs = child_search(pid, psscan_output)
            target_child_processes.append(childs)
    return target_child_processes

def report_analysis(report_path):

    content = open(report_path, 'rt').read()
    malware_name = report_path.split('_')[-1].split('.')[0]
    heur_vector = []
    #1) ## executable file not in pslist

    processes_section = content[content.find('New pslist entries'):content.find('New netscan entries.')]
    pslist_output = processes_section[processes_section.find('New pslist entries'):processes_section.find('New psscan entries')]
    pslist_output = pslist_output.split('\n')
    pslist_flag = True
    for entry in pslist_output:
        if malware_name in entry:
            pslist_flag=False
    heur_vector.append(pslist_flag)

    #2) ## executable file not in pslist but in psscan/psxview

    psscan_psxview_output = processes_section[processes_section.find('New psscan entries'):]
    psscan_psxview_output = psscan_psxview_output.split('\n')
    psscan_psxview_presence_flag = False
    for entry in psscan_psxview_output:
        if malware_name in entry:
            psscan_psxview_presence_flag = True
    if psscan_psxview_presence_flag and pslist_flag:
        psscan_psxview_flag = True
    else:
        psscan_psxview_flag = False
    heur_vector.append(psscan_psxview_flag)

    #3) ## non-system processes open connection
 
    psscan_output = processes_section[processes_section.find('New psscan entries'):processes_section.find('New psxview entries')]
    psscan_output = psscan_output.split('\n')
    netscan_different_pid_connection_flag = False
    target_application_pid = ''
    pids = []
    for entry in psscan_output[4:-3]:
        entry = entry.split()
        pids.append(entry[2])
        if malware_name in entry[1]:
            target_application_pid = entry[2]
    child_processes = child_search(target_application_pid, psscan_output)
    if re.search(r'New netscan entries', content):
        tmp_str = content[content.find('New netscan entries.'):content.find('No notable changes to highlight from the following plugins.')]
        netscan_output = tmp_str[tmp_str.find(tmp_str.split('\n')[2]):tmp_str[tmp_str.find(tmp_str.split('\n')[2]):].find('==========================================================================================================================')].split('\n')
        for entry in netscan_output[3:-4]:
            entry = entry.split()
            if entry[4] == 'LISTENING':
                pid = entry[5]
            else:
                pid = entry[4]
            if pid in pids:
                netscan_different_pid_connection_flag = True
    heur_vector.append(netscan_different_pid_connection_flag)

    #4) ## non-local connections

    non_local_connections_flag = False
    for entry in netscan_output[3:-4]:
        local_addr = entry.split()[2]
        foreign_addr = entry.split()[3]
        if local_addr.startswith('0.0.0.0') or local_addr.startswith('192.168.') or local_addr.startswith(':::') or local_addr.startswith('-:') or local_addr.startswith('127.'):
            pass
        else:
            non_local_connections_flag = True
    heur_vector.append(non_local_connections_flag)

    #5) ## malfind injections

    malfind_flag = bool(re.search(r"New malfind entries.", content))
    heur_vector.append(malfind_flag)

    #6) ## MZ signature in malfind

    MZ_signature_flag = False
    if malfind_flag:
        tmp_str = content[content.find('New malfind entries.'):content.find('No notable changes to highlight from the following plugins.')]
        malfind_output = tmp_str[tmp_str.find(tmp_str.split('\n')[2]):tmp_str[tmp_str.find(tmp_str.split('\n')[2]):].find('==========================================================================================================================')].split('\n')
        for entry in malfind_output:
            if 'MZ.' in entry:
                MZ_signature_flag = True
    heur_vector.append(MZ_signature_flag)

    #7) ## possible privs escalation

    new_privs_flag = bool(re.search(r'New privs entries.', content))
    heur_vector.append(new_privs_flag)

    #8) ## cmd, conhost, powershell in processes

    cmd_ps_process_flag = False
    processes = []
    for entry in psscan_output[4:-3]:
        entry = entry.split()
        processes.append(entry[1])
    if re.search('cmd|conhost|powershell', '\n'.join(processes), re.IGNORECASE):
        cmd_ps_process_flag = True
    heur_vector.append(cmd_ps_process_flag)

    #9) ## envras flag

    new_envs_flag = bool(re.search(r'New envars entries.', content))
    heur_vector.append(new_envs_flag)

    #10) ## new hashdump

    new_hashdump_flag = bool(re.search(r'New hashdump entries.', content))
    heur_vector.append(new_hashdump_flag)

    #11) ## new cmdline

    new_cmdline_flag = bool(re.search(r'New cmdline entries.', content))
    heur_vector.append(new_cmdline_flag)

    #12) ## unexpected parent

    unexpected_parent_flag = bool(re.search(r'Unexpected parent process', content))
    heur_vector.append(unexpected_parent_flag)

    #13) ## parent absence

    parent_absence_flag = bool(re.search(r'is not listed in psscan output.', content))
    heur_vector.append(parent_absence_flag)

    #14) ## possible lateral movement, exfiltration

    bad_processes_flag = bool(re.search(r'Process(es) that may have been used for lateral movement, exfiltration etc', content))
    heur_vector.append(bad_processes_flag)

    #15) ## Process hollowing

    hollowing_flag = bool(re.search(r'Potential process hollowing detected', content))
    heur_vector.append(hollowing_flag)

    #16) ## Suspicious dll

    susp_dll_exe_flag = False
    if 'Suspicious DLLs/EXEs (dlllist).' in content:
        susp_dll_section = content[content.find('Suspicious DLLs/EXEs (dlllist).'):content.find('Hidden/suspicious DLLs/EXEs')].split('\n')
    #     print(susp_dll_section[2:-3])
        for path in susp_dll_section[2:-3]:
            if re.search('syswow64|system32|winsxs', path, re.IGNORECASE):
                pass
            else:
                susp_dll_exe_flag = True
    heur_vector.append(susp_dll_exe_flag)

    #17) ## Too much dll

    too_much_dll_flag = False
    if 'Warning: too many entries to report, output truncated!' in susp_dll_section:
        too_much_dll_flag = True
    heur_vector.append(too_much_dll_flag)

    #18) ## non system ldrmodules

    susp_ldr_flag = False
    if re.search(r"Hidden/suspicious DLLs/EXEs", content):
        tmp_str = content[content.find('Hidden/suspicious DLLs/EXEs'):]
        # print(tmp_str[tmp_str.find(tmp_str.split('\n')[4]):])
        susp_ldr_section = tmp_str[tmp_str.find(tmp_str.split('\n')[4]):tmp_str[325:].find('==========================================================================================================================')].split('\n')
        # print(susp_ldr_section)
        for path in susp_ldr_section:
            if re.search('syswow64|system32|winsxs', path, re.IGNORECASE):
                pass
            else:
                susp_ldr_flag = True
    heur_vector.append(susp_ldr_flag)

    #19) ## Too much files

    too_much_files_accessed_flag = False
    if re.search('Interesting files on disk .filescan.', content):
        tmp_str = content[content.find('Interesting files on disk (filescan).'):]
        files_accessed_section = tmp_str[tmp_str.find(tmp_str.split('\n')[2]):tmp_str[161:].find('==========================================================================================================================')].split('\n')
        # print(files_accessed_section)
        # print(susp_ldr_section)
        if 'Warning: too many entries to report, output truncated!' in files_accessed_section:
            too_much_files_accessed_flag = True
    heur_vector.append(too_much_files_accessed_flag)

    #20) ## svcscan flag

    svcscan_flag = bool(re.search(r'Notable new entries from svcscan.',content))
    heur_vector.append(svcscan_flag)

    #21) ## gditimers flag

    gditimers_flag = bool(re.search(r'Unusual gditimers.',content))
    heur_vector.append(gditimers_flag)

    #22) ## mutants flag

    mutant_flag = bool(re.search(r'Mutants accessed (handles):',content))
    heur_vector.append(mutant_flag)

    #23) ## collects info in registry

    collect_info_reg_flag = bool(re.search(r'Collects information about system:',content))
    heur_vector.append(collect_info_reg_flag)

    #24) ## Internet settings in registry

    internet_set_flag = bool(re.search(r'Queries / modifies proxy settings:',content))
    heur_vector.append(internet_set_flag)

    #25) ## access to autorun

    autorun_reg_flag = bool(re.search(r'Has access to autorun registry keys:',content))
    heur_vector.append(autorun_reg_flag)

    #26) ## recieve or send files internet

    int_recieve_send_flag = bool(re.search(r'Can receive or send files from or to internet',content))
    heur_vector.append(int_recieve_send_flag)

    #27) ## sysinfo enumerate

    sysinfo_enum_flag = bool(re.search(r'Can enumerate system information',content))
    heur_vector.append(sysinfo_enum_flag)

    #28) ## Clipboard access

    clipboard_flag = bool(re.search(r'Can access the clipboard',content))
    heur_vector.append(clipboard_flag)

    #29) ## query startup info

    startup_info_flag = bool(re.search(r'Can query startup information',content))
    heur_vector.append(startup_info_flag)

    #30) ## code injection

    inject_flag = bool(re.search(r'Can inject code to other processes',content))
    heur_vector.append(inject_flag)

    #31) ## virtualalloc usage

    virtualloc_flag = bool(re.search('virtualalloc|virtualallocex', content, re.IGNORECASE))
    heur_vector.append(virtualloc_flag)

    #32) ## create or write to files

    create_write_files_flag = bool(re.search('Can create or write to files', content, re.IGNORECASE))
    heur_vector.append(create_write_files_flag)

    #33) ## UAC bypass

    UAC_flag = bool(re.search('Can bypass UAC', content, re.IGNORECASE))
    heur_vector.append(UAC_flag)

    #34) ## interact with device drivers

    device_drivers_flag = bool(re.search('Can interact with or query device drivers', content, re.IGNORECASE))
    heur_vector.append(device_drivers_flag)

    #35) ## restarting system

    restart_system_flag = bool(re.search('Can restart or shutdown the system', content, re.IGNORECASE))
    heur_vector.append(restart_system_flag)

    #36) ## keyboard strokes

    strokes_flag = bool(re.search('Can track keyboard strokes', content, re.IGNORECASE))
    heur_vector.append(strokes_flag)

    #37) ## Shell keyword(s)

    shell_flag = bool(re.search('Shell keyword', content, re.IGNORECASE))
    heur_vector.append(shell_flag)

    #38) ## Web related keyword

    web_flag = bool(re.search('Web related keyword', content, re.IGNORECASE))
    heur_vector.append(web_flag)

    #39) ## Browser keyword

    browser_flag = bool(re.search('Browser keyword', content, re.IGNORECASE))
    heur_vector.append(browser_flag)

    #40) ## Encryption keyword

    encryption_flag = bool(re.search('Encryption keyword', content, re.IGNORECASE))
    heur_vector.append(encryption_flag)

    #41) ## Executable files

    exe_files_flag = bool(re.search('Executable file', content, re.IGNORECASE))
    heur_vector.append(exe_files_flag)

    #42) ## Password keyword

    credential_flag = bool(re.search("Password keyword", content, re.IGNORECASE))
    heur_vector.append(credential_flag)

    #43) ## Remote control

    remote_control_flag = bool(re.search("modifies remote control settings", content, re.IGNORECASE))
    heur_vector.append(remote_control_flag)

    #44) ## HTTP URL(S)

    url_flag = bool(re.search('HTTP URL', content, re.IGNORECASE))
    heur_vector.append(url_flag)

    #45) ## unusual session

    run_in_unusual_session = False
    if re.search(r'running in an unusual session', content):
        run_in_unusual_session = True
    heur_vector.append(run_in_unusual_session)

    #46) ## child processes

    child_processes_flag = False
    if child_processes:
        child_processes_flag = True
    heur_vector.append(child_processes_flag)

    #47) ## IP addresses string

    ip_string_flag = False
    if re.search(r'IP address', content):
        ip_string_flag = True
    heur_vector.append(ip_string_flag)

    #48)

    email_string_flag = False
    if re.search(r'Email', content):
        email_string_flag = True
    heur_vector.append(email_string_flag)

    #49) ## Unexpected application path

    unexpected_path_flag = False
    if re.search(r'running from an unexpected path', content):
        unexpeced_path_flag = True
    heur_vector.append(unexpected_path_flag)


    vector = list([int(h) for h in heur_vector])
    print(vector)
    heur_dict = {'target application not in psslist': 1, 'target application in psscan but not in pslist': 2, 'non-system process opens network connection': 3, 'external connections were opened': 4, 'possible code injection': 5, 'MZ signature in injection': 6, 'possible privelleges escalation': 7, 'cmd, conhost or powershell in processes': 8, 'envars modification': 9, 'new hashdump entries': 10, 'new cmdline entries': 11, 'some process(es) have unexpected parent': 12, 'parent process is not in pslist/psscan': 13, 'possible lateral movement/exfiltration': 14, 'possible process hollowing techniques': 15, 'possibly suspicious dlls': 16, 'Too much imported dlls': 17, 'non system dlls in ldrmodules': 18, 'Too much files accessed': 19, 'new svc entries': 20, 'unusual gditimers': 21, 'new mutexes': 22, 'collecting information from regestry': 23, 'Queries internet settings in regestry': 24, 'Accessing autorun section': 25, 'can recieve or send files to internet': 26, 'Enumerate system information ': 27, 'Clipboard access': 28, 'Access startup information': 29, 'possible code injection in processes': 30, 'using VirtualAlloc function': 31, 'can create or write to files': 32, 'Posibly using UAC bypass techniques': 33, 'Can interact with device drivers': 34, 'Can restart system': 35, 'Check for keyboard strokes': 36, 'Shell keywords in processes': 37, 'Web related keyword in processes': 38, 'Browser keyword in processes': 39, 'Encryption related keywords in processes': 40, 'Executable filename in procesess': 41, 'Credential related keywords in processes': 42, 'Remote contorl settings in registry': 43, 'HTTP/URL related keywords in processes': 44, 'process in unusual session': 45, 'target app creates child processes': 46, 'IP string in processes': 47, 'Email string in processes': 48, 'Unexpected application path': 49}
    h_d = dict()
    for value, key in heur_dict.items():
        h_d[key] = value
    # with open('/home/cuckoo/PycharmProjects/vm_manage/VolDiff/reports/heuristics.txt', 'at') as f:
        # f.writelines(malware_name+'\t'+str(vector)+'\n')
    with open(f'{MINI_REPORT_PATH}{malware_name}_report_mini.txt','wt') as f:
        for i in range(1, len(heur_vector)+1):
            if heur_vector[i-1]:
                f.write(h_d[i]+'\n')
    with open(MINI_REPORT_PATH + 'tmp.txt', 'wt') as f:
        f.write(str(vector))


def hash_calc(malware_path=MALWARE):
    pe = pefile.PE(malware_path)
    imp_hash = pe.get_imphash()
    ssdeep_hash = ssdeep.hash_from_file(malware_path)
    sha = sha1(open(malware_path, 'rb').read()).hexdigest()
    return imp_hash, ssdeep_hash, sha

def memory_capturing():
    print('[+] Starting the sandbox')
    cmd1 = subprocess.run(f'vmrun -T ws start {SANDBOX_PATH} nogui'.split(' '), stdout=subprocess.PIPE)
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


def main():
    try:
        hashes = hash_calc(MALWARE)
        print(f'{MALWARE_NAME} imphash: {hashes[0]}', f'{MALWARE_NAME} ssdeep hash: {hashes[1]}', sep='\t', end='\n')
    except Exception as e:
        print(e)
        sys.exit()
    try:
        inf_snap = memory_capturing()
    except Exception as e:
        print('smth went wrong when sandbox was running, reverting sandbox...')
        print(e)
        subprocess.run(f'vmrun -T ws revertToSnapshot {SANDBOX_PATH} '
                            f'{CLEAR_SNAPSHOT_NAME}'.split(' '), stdout=subprocess.PIPE)
        sys.exit()
    try:
        subprocess.call(['python2', VOLDIFF_PATH, clean_snap, inf_snap, PROFILE, '--output-dir', OUTPUT_DIR, '--malware-checks'])
    except Exception as e:
        print('smth went wrong when VolDiff was executing, stopping VolDiff...')
        print(e)
        if os.path.exists(OUTPUT_DIR):
            for root, dirs, files in os.walk(output_dir):
                for f in files:
                    os.unlink(os.path.join(root, f))
                for d in dirs:
                    shutil.rmtree(os.path.join(root, d))
        if os.path.exists(REPORT_PATH):
            os.remove(REPORT_PATH)
        if os.path.exists(inf_snap):
            os.remove(inf_snap)
        sys.exit()
    try:
        heur_vector = report_analysis(REPORT_PATH)
    except Exception as e:
        print('smth went wrong when the report was analyzing, stopping analyzer...')
        print(e)
        if os.path.exists(inf_snap):
            os.remove(inf_snap)
        sys.exit()
    if not SAVE_DUMP_FLAG:
        os.remove(inf_snap)
        print('\n\n[+] Infected snapshot was totally deleted')
    else:
        print('\n\n[+] Infected snapshot saved %s' % inf_snap)

    print(f'\n[+] Full report created in {REPORT_PATH}\n')
    malwr_mini_name = REPORT_PATH.split('_')[-1].split('.')[0]
    mini_report_path = f'{MINI_REPORT_PATH}{malwr_mini_name}_report_mini.txt'
    print(f'\n[+] Mini report created in {mini_report_path}')
    ## try:
        ## with open(REPORT_PATH, 'at') as fp:
            ## print(f'\n{MALWARE_NAME} sha1: {hashes[2]}', f'{MALWARE_NAME} imphash: {hashes[0]}', f'{MALWARE_NAME} ssdeep hash: {hashes[1]}', sep='\n', end='\n\n', file=fp)
    ## except:
        ## pass
    if os.path.exists(RESULT_PATH):
        shutil.rmtree(RESULT_PATH)
    os.mkdir(RESULT_PATH)
    shutil.copyfile(REPORT_PATH, RESULT_PATH+REPORT_PATH.split('/')[-1])
    shutil.copyfile(mini_report_path, RESULT_PATH+mini_report_path.split('/')[-1])
    copy_tree(SCREENS_PATH, RESULT_PATH+'screens/')
    if os.path.exists(f'{CWD}result.zip'):
        os.remove(f'{CWD}result.zip')
    shutil.make_archive('result', 'zip', RESULT_PATH)

main()

