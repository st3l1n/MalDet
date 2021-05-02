SAVE_DUMP_FLAG = False
DELAY = 20
CWD = '/MalDet/maldet/MalDet/'
RESULT_PATH = f'{CWD}result/'
SANDBOX_PATH = '/home/cuckoo/vmware/MDB/MDB.vmx'
clean_snap = f'{CWD}clean_state.vmem'
PROFILE = 'Win7SP1x64_24000'
VOLDIFF_PATH = f'{CWD}VolDiff.py'
OUTPUT_DIR = f"{CWD}VolDiff_reports/reports/full/VolDiff_output"
CLEAR_SNAPSHOT_NAME = 'clean_state'
SANDBOX_USERNAME = 'MalDet'
SANDBOX_PASSWORD = 'MalDet'
SANDBOX_CONF = '/home/cuckoo/vmware/MDB/sandbox.conf'
MINI_REPORT_PATH = f'{CWD}VolDiff_reports/reports/mini/'
REPORT_PATH = f"{CWD}VolDiff_reports/reports/full/"
SANDBOX_MALWARE_PATH = 'C:\\Users\\MalDet\\Desktop\\Malware\\'
ARCHIVE_PATH = f'{CWD}result.zip'

TF_MODEL = "resnet_malware_detection_tf_2.4.hdf5"
EMBER_MODEL = "ember_model_2018.txt"
UPLOAD_DIRECTORY = "./files"

