# MalDet Framework: tool for malware analysis and incident response

## Caption
This is my graduation work on malware analysis with computer vision and behavioural malware analysis with custom sandbox for improving incident response process. 

## Disclaimer
BE CAREFUL! This module do not designed for enterprise or commerce usage. There are no any security                               features and It won't work with heavy load. You can use it for malware analysis in your own environment       or just take some code and methodology patterns.

## Framework consists of two modules:
>  * Signature analysis module based on computer vision technology and yara framework
>  * Behavioural analysis module based on custom sandbox in VMWare 

## Signature analysis module

Signature analysis module represents [ResNet50](https://www.tensorflow.org/api_docs/python/tf/keras/applications/ResNet50) neural net wrapped with flask framework in server side and console python3 script that interact with server via REST API. **It's only detects malware without classification**. You can find model weights [here](https://mega.nz/file/FZwkzb7J#f55p4e12hzNWCvlb3W1333rF3ACCcMUiUOZVuFE5d-g) (model accuracy was about 98,16%), but make sure that you want to use this weights, because training dataset was not good enough for real environment. You always can download this weights for transfer learning your own model.

To turn on the server you need to run MalDetS.ipynb in your jupyter (or convert it to python script and run with console). On default it maps server on port 8003. Server logs some info to log file and stores analysis information in SQLite database.

To interact with the server you have to be in the same net area and just run script **MalDetS_client.py** with proper params.
 ### Requirments
 - tensorflow==2.4
 - flask
 - pillow
 - numpy

<details>
  <summary markdown="span">Here you can see how to use MalDetS_client.py</summary>

`usage: MalDetS_Client.py [-h] [--version] {analyze,search,list_files} ...`


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
 - **analyze** is a core function, which represents analysis functionality. Positional argumets are `ip` - ip address of analysis server and `filepath` - path to file which you want to analyze. There are also two optional arguments: `--dir` and `--mode`. `--dir` param indicates that a `filepath` param is a dir and module has to analyze all files in that dir. `--mode` param represents analysis mode. 0 returns only type of a file (means if it is malware or not) and 1 returns full analysis info. So if you want to use this function it should look like `python3 MalDetS_Client.py analyze <ip addr of server> <path to file for analysis>` 
 - **search** function helps to search results in server database. This function requires one positional argument `ip` which means the same. By default it would search by hash value, so your command should look like `python3 MalDetS_Client.py search <sha512_hash_value>`. You can also specify some optional arguments like `--search_mode` and `--search_arg`. `--search_mode ` param can be `h`, `i` or `d`: `h` is default hash option, `i` for search depends on ip address of client who made analysis (returns all results made by this ip) and `d` for search by date. `--search_arg` depends on `--search_mode`. For hash it should be valid sha512 hash value, for ip it should be valid ip address, for date it should be date in format dd/mm/yyyy. So your command can be `python3 MalDetS_Client.py search --search_mode i --search_arg <ip address>`   
 
 </details>
