#!/usr/bin/env python
# coding: utf-8

# # Samples Transfromation Section

# In[1]:


import os, math
import argparse
from PIL import Image

def getBinaryData(filename):
    """
    Extract byte values from binary executable file and store them into list
    :param filename: executable file name
    :return: byte value list
    """

    binary_values = []

    with open(filename, 'rb') as fileobject:

        # read file byte by byte
        data = fileobject.read(1)

        while data != b'':
            try:
                binary_values.append(ord(data))
            except MemoryError:
                with open('not_processed_files.txt', 'at') as f:
                    f.write(filename+'\n')
                    return False
            data = fileobject.read(1)

    return binary_values

def save_file(filename, data, size, image_type):
    try:
        image = Image.new(image_type, size)
        image.putdata(data)

        # setup output filename
        dirname = os.path.dirname(filename)
        name, _ = os.path.splitext(filename)
        name = os.path.basename(name)
        imagename = dirname + os.sep + image_type + os.sep + name + '_'+image_type+ '.png'
        os.makedirs(os.path.dirname(imagename), exist_ok=True)

        image.save(imagename)
        return imagename
    except Exception as err:
        print(err)
        
def get_size(data_length, width=None):
    # source Malware images: visualization and automatic classification by L. Nataraj
    # url : http://dl.acm.org/citation.cfm?id=2016908

    if width is None: # with don't specified any with value

        size = data_length

        if (size < 10240):
            width = 32
        elif (10240 <= size <= 10240 * 3):
            width = 64
        elif (10240 * 3 <= size <= 10240 * 6):
            width = 128
        elif (10240 * 6 <= size <= 10240 * 10):
            width = 256
        elif (10240 * 10 <= size <= 10240 * 20):
            width = 384
        elif (10240 * 20 <= size <= 10240 * 50):
            width = 512
        elif (10240 * 50 <= size <= 10240 * 100):
            width = 768
        else:
            width = 1024

        height = int(size / width) + 1

    else:
        width  = int(math.sqrt(data_length)) + 1
        height = width

    return (width, height)


def createRGBImage(filename, width=None):
    """
    Create RGB image from 24 bit binary data 8bit Red, 8 bit Green, 8bit Blue
    :param filename: image filename
    """
    index = 0
    rgb_data = []

    # Read binary file
    binary_data = getBinaryData(filename)
    if not binary_data:
        return False
    # Create R,G,B pixels
    while (index + 3) < len(binary_data):
        R = binary_data[index]
        G = binary_data[index+1]
        B = binary_data[index+2]
        index += 3
        rgb_data.append((R, G, B))

    size = get_size(len(rgb_data), width)
    imagename = save_file(filename, rgb_data, size, 'RGB')
    return imagename


# # Model Loading Section

# In[ ]:


##import tensorflow as tf
##print(tf.__version__())
##from tensorflow.keras.models import load_model
##model = load_model("final.hdf5")
##print(type(model))


# # Model Predicting Section

# In[ ]:


##from tensorflow.keras.preprocessing import image

def predict_image(model, img_path):
    # Read the image and resize it
    img_width, img_height = 224, 224
    img = image.load_img(img_path, target_size=(img_height, img_width))
    # Convert it to a Numpy array with target shape.
    x = image.img_to_array(img)
    # Reshape
    result = model.predict([x])[0][0]
    if result > 0.5:
        file_type = "malware"
    else:
        file_type = "benign"
        result = 1 - result
    return file_type,result


# # Cuckoo Communication Section  

# In[ ]:

def cuckoo_analysis(path_to_file: str):
    security_token = '<Some_Token>'
    ANALYSIS_URL = "http://localhost:8090/tasks/create/file"
    HEADERS = {"Authorization": 'Bearer {%s}' % security_token}

    with open(path_to_file, "rb") as sample:
        file = {"file": ("temp_file_name", sample)}
        submit_to_analysis_request = requests.post(ANALYSIS_URL, headers=HEADERS, files=file)

    task_id = submit_to_analysis_request.json()["task_id"]
    STATE_URL = 'http://localhost:8090/tasks/view/%d' % task_id
    
    while True:
        checking_state_request = requests.get(STATE_URL, headers=HEADERS)
        status = checking_state_request.json()["task"]["status"]
        if status != 'reported':
            continue
        else:
            break
    REPORT_URL = "http://localhost:8090/tasks/report/%d/html" % task_id
    getting_report_request = requests.get(REPORT_URL, headers=HEADERS)
    return getting_report_request.content


# # Server Section

# In[ ]:


import os

from flask import Flask, request, abort, jsonify, send_from_directory


UPLOAD_DIRECTORY = "./files"

if not os.path.exists(UPLOAD_DIRECTORY):
    os.makedirs(UPLOAD_DIRECTORY)


api = Flask(__name__)


@api.route("/files")
def list_files():
    """Endpoint to list files on the server."""
    files = []
    for filename in os.listdir(UPLOAD_DIRECTORY):
        path = os.path.join(UPLOAD_DIRECTORY, filename)
        if os.path.isfile(path):
            files.append(filename)
    return jsonify(files)


@api.route("/files/<path:path>")
def get_file(path):
    """Download a file."""
    return send_from_directory(UPLOAD_DIRECTORY, path, as_attachment=True)

@api.route("/files/<filename>/<mode>", methods=["POST"])
def post_file(filename, mode):
    """Upload a file."""

    if "/" in filename:
        # Return 400 BAD REQUEST
        abort(400, "no subdirectories allowed")

    with open(os.path.join(UPLOAD_DIRECTORY, filename), "wb") as fp:
        fp.write(request.data)
    
    # Return 201 CREATED
    return f"{mode}", 201


if __name__ == "__main__":
    api.run(host='0.0.0.0',debug=True, port=8000,use_reloader=False)


# In[ ]:




