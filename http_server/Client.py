#!/usr/bin/env python
# coding: utf-8

# In[11]:


import requests
import time
import animation

API_URL = 'http://localhost:8000'
API_KEY = 'i0cgsdYL3hpeOGkoGmA2TxzJ8LbbU1HpbkZo8B3kFG2bRKjx3V'

headers = {'UserAPI-Key': API_KEY}


# In[15]:


# response = requests.get('{}/files'.format(API_URL), headers=headers)
# print(response.json())


filename = "misc.xml"
@animation.wait('spinner')
def upload_file(filename: str, mode: int):
    with open(filename, "rb") as fd:
        data = fd.read()
    print('Uploading...')
    time.sleep(5)
    response = requests.post(
        f'{API_URL}/files/{filename}/{mode}', headers=headers, data=data)
    print('Done uploading\n', response.status_code, response.text)

@animation.wait('spinner')
def download_file(filename: str):
    print('Downloading...')
    time.sleep(5)
    response = requests.get(
        f'{API_URL}/files/{filename}', headers=headers)
    print('Done downloading...\n', response.status_code)

upload_file(filename, 2)
download_file(filename)


# In[ ]:




