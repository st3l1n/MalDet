# MalDet Framework: tool for malware analysis and incident response

## Caption
This is my graduation work on malware analysis with machine learning algorithms and behavioural malware analysis in custom sandbox for incident response process perfomance improving. 

## Disclaimer
BE CAREFUL! This module do not designed for enterprise or commerce usage. There are no any security                               features and It won't work with heavy load. You can use it for malware analysis in your own environment       or just take some code and methodology patterns.

## Framework consists of two modules:
>  * Signature analysis module based on computer vision technology and yara framework
>  * Behavioural analysis module based on custom sandbox in VMWare 

### Sys requirments(server side)
 - python 2.7 and python 3.6 or higher
 - vmware workstation 15 or higher
 - volatility 2.6 installed as a lib
 - some files and folders manipulations (see behavioural module docs)

### Requirments(server side python3)
 - tensorflow==2.4
 - flask
 - pillow
 - ember
 - ssdeep
 - pefile

### Requirments(server side python2)
 - distorm3
 - yara
 - pycrypto
 - openpyxl
 - simplejson
 
### Requirments(client side python3)
 - pyfiglet
 - requests

## Signature analysis module

Signature analysis module represents [ResNet50](https://www.tensorflow.org/api_docs/python/tf/keras/applications/ResNet50) neural net and the latest [ember](https://github.com/elastic/ember) module wrapped with flask framework in server side and console python3 script that interact with server via REST API. **It's only detects malware without classification**. You can find model weights [here](https://mega.nz/file/FZwkzb7J#f55p4e12hzNWCvlb3W1333rF3ACCcMUiUOZVuFE5d-g) (model accuracy was about 98,16%), but make sure that you want to use this weights, because training dataset was not good enough for real environment. You always can download this weights for transfer learning your own model. Static analysis also includes fuzzy hash comapring (ssdeep) and impahash comparing with sample that were already analyzed.

## Behavioural analysis module

**Temporary limits of that module is that the module analyzes only PE executable files. Maybe I'll fix this later.**

<details>
  <summary markdown="span">Some system manipulations</summary>
 
 The best way is to create separate folder(MalDet for example =) ). This folder must be organised inside in that way:
```
MalDet
├── all_results
├── clean_state.vmem
├── ember_model_2018.txt
├── files
│   └── RGB
├── Infected_dumps
├── MalDet.db
├── MalDet.py
├── __pycache__
│   └── set.cpython-36.pyc
├── resnet_malware_detection_tf_2.4.hdf5
├── result
├── sandbox.py
├── screens
├── set.py
├── tmp
├── VolDiff.py
└── VolDiff_reports
    └── reports
        ├── full
        │   └── VolDiff_output
        ├── heuristics.txt
        └── mini
```
Thx a lot to this [guys](https://github.com/H2Cyber/VolDiff) for providing a nice tool for memory forensics. **Be carefull, this script little bit different compare to original.**
All global params written in *set.py*. You need to create your own sandbox VM. It can be any win system you want, you can customize any tools inside vm (like office, tcpdump, fakenet etc). But this example uses "naked" win7 with all security features disabled.
</details>

Behaviuoral module uses memory forensics survey for malware analysis. Malware runs in isolated program env (VMWare), than infected dump is being compared with clean dump using VolDiff. After that possible malicious heuristics (50 different heuristics) are being extracted from report. Criminalist gets archive with screens from VM, full report and mini report. Of course lots of malware detects VMWare unfortunately, so you can move VM to KVM or QEMU.

## Usage
To turn on the server you need to run `python3 MalDet.py` in your console. It maps server on port 8003. Server logs some info to stdout and stores analysis information in SQLite database.

To interact with the server you have to be in the same net area and just run script **Client.py** with proper params.

<details>
  <summary markdown="span">Here you can see how to use Client.py</summary>

`usage: Client.py [-h] [--version] {analyze,search,list_files} ...`


```
positional arguments:
  {analyze,search,list_files}
                        list of commands
    analyze             file analysis options
    search              search options
    list_files          all files analyzed

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  ```
 Each command has it's own arguments:
 - **analyze** is a core function, which represents analysis functionality. Positional argumets are `ip` - ip address of analysis server and `filepath` - path to file which you want to analyze. There are also two optional arguments: `--dir` and `--mode`. `--dir` param indicates that a `filepath` param is a dir and module has to analyze all files in that dir. `--mode` param represents analysis mode. 0 returns only type of a file (means if it is malware or not) and 1 returns full analysis info. So if you want to use this function it should look like `python3 Client.py analyze <ip addr of server> <path to file for analysis>`. If you choose mode=2 be ready to wait some time (10 mins for benign samples and about 15-20 mins for malware).
 - **search** function helps to search results in server database. This function requires one positional argument `ip` which means the same. By default it would search by hash value, so your command should look like `python3 Client.py search <sha512_hash_value>`. You can also specify some optional arguments like `--search_mode` and `--search_arg`. `--search_mode ` param can be `h`, `i` or `d`: `h` is default hash option, `i` for search depends on ip address of client who made analysis (returns all results made by this ip) and `d` for search by date. `--search_arg` depends on `--search_mode`. For hash it should be valid sha1 hash value, for ip it should be valid ip address, for date it should be date in format dd/mm/yyyy. So your command can be `python3 Client.py search --search_mode i --search_arg <ip address>`   
If you want to serach dynamic analysis results, you can specify `--mode 2` in search request. Only hash mode usable for dynamic search/ 
 </details>


