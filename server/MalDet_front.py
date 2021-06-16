#!/usr/bin/env python
# coding: utf-8

# In[18]:


import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"
import shutil
import ember
import lightgbm as lgb
from tensorflow.keras.models import load_model
from datetime import datetime
import math
import argparse
from PIL import Image
from tensorflow.keras.preprocessing import image
from tensorflow.keras.applications.resnet50 import preprocess_input
import numpy as np
import sqlite3
import json
from flask import Flask, request, abort, jsonify, send_file, make_response
from hashlib import sha1
import re
import base64
import subprocess
import ssdeep
import pefile
from set import TF_MODEL, EMBER_MODEL, UPLOAD_DIRECTORY, CWD
from flask_cors import CORS, cross_origin


tf_model = load_model(TF_MODEL)
ember_model = lgb.Booster(model_file=EMBER_MODEL)
if not os.path.exists(UPLOAD_DIRECTORY):
    os.makedirs(UPLOAD_DIRECTORY)


def hash_calc(malware_path):
    # print(malware_path)
    pe = pefile.PE(malware_path)
    imp_hash = pe.get_imphash()
    ssdeep_hash = ssdeep.hash_from_file(malware_path)
    sha = sha1(open(malware_path, 'rb').read()).hexdigest()
    return imp_hash, ssdeep_hash, sha


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


def predict_image(model, img_path):
    # Read the image and resize it
    img_width, img_height = 224, 224
    img = image.load_img(img_path, target_size=(img_height, img_width))
    # Convert it to a Numpy array with target shape.
    x = image.img_to_array(img)
    x = np.expand_dims(x, axis=0)
    x = preprocess_input(x)
    # Reshape
    result = model.predict(x)
    if result > 0.5:
        file_type = "malware"
    else:
        file_type = "benign"
        result = 1 - result
    return file_type, float(result)


def search_for_matches(conn, filename: str, ssdeep_hash: str, imphash: str, sha: str):
    matches = []
    update_flag = False
    search_query = """SELECT imphash, ssdeep, filename, sha_1, possible_matches from MalDet_S"""
    conn.execute(search_query)
    rows = conn.fetchall()
    if rows:
        for row in rows:
            tmp_imphash = row[0]
            tmp_ssdeep = row[1]
            tmp_filename = row[2]
            tmp_sha = row[3]
            tmp_matches = row[4]
            if tmp_matches:
                tmp_matches = eval(tmp_matches)
            else:
                tmp_matches = []
            if tmp_imphash:
                if imphash == tmp_imphash:
                    matches.append({'filename': tmp_filename,'reason': 'imphash equality', 'matching_sha_1': tmp_sha})
                    tmp_matches.append({'filename': filename, 'reason': 'imphash equality', 'matching_sha_1': sha})
                    update_flag = True
            if tmp_ssdeep:
                ssdeep_result = ssdeep.compare(ssdeep_hash, tmp_ssdeep) 
                if ssdeep_result:
                    matches.append({'filename': tmp_filename, 'reason': 'ssdeep similarity: %d' % ssdeep_result, 'matching sha_1': tmp_sha})
                    tmp_matches.append({'filename': filename, 'reason': 'ssdeep similarity: %d' % ssdeep_result, 'matching sha_1': sha})
                    update_flag = True
            if update_flag:
                tmp_matches = str(tmp_matches)
                update_query = """UPDATE MalDet_S set possible_matches = \"%s\" where sha_1 = \"%s\"""" % (tmp_matches, sha)
                conn.execute(update_query)
    return str(matches)   



def analysis(filename=0, data=0, mode=0, mfl=False, ip=''):
    FLAG_S=False
    FLAG_B = False
    conn = sqlite3.connect("MalDet.db")
    c = conn.cursor()
    if data:
        path_to_file = os.path.join(UPLOAD_DIRECTORY,filename)
        with open(path_to_file, "wb") as fp:
            fp.write(data)
    if filename and not data:
        if mfl:
            path_to_file = filename
        else:
            path_to_file = os.path.join(UPLOAD_DIRECTORY,filename) 
        with open(path_to_file, 'rb') as f:
            data = f.read()
    try:
        check = pefile.PE(path_to_file)
    except pefile.PEFormatError:
        err = {'error': 'this is not PE file'}
        return err
    imphash, ssdeep_hash, sha = hash_calc(path_to_file)
    c.execute("""SELECT sha_1 from MalDet_S
    where sha_1=?""", (sha,))
    rows = c.fetchall()
    if rows:
        FLAG_S = True
    c.execute("""SELECT sha1_hash from MalDet_B
    where sha1_hash=?""", (sha,))
    rows1 = c.fetchall()
    if rows1:
        FLAG_B = True
    if FLAG_S and mode != '2':
        # print('existing file, searching...')
        c.execute("""SELECT * from MalDet_S
    where sha_1=?""", (sha,))
        rows = c.fetchall()
        conn.commit()
        conn.close()
        return unit_pack(rows, mode)
    elif FLAG_B and mode == '2':
        # print('existing file, searching...')
        readBlob(sha)
    else:
        # print("new file, processing...")
        if mfl == True:
            filepath = filename
        else:
            filepath = os.path.join(UPLOAD_DIRECTORY, filename)
        if not FLAG_S:
            if os.path.getsize(filepath) > 1500000:
                data = open(filepath, "rb").read()
                prob = ember.predict_sample(ember_model, data)
                if prob >= 0.5:
                    result = ('malware', prob)
                else:
                    result = ('benign', 1-prob)
            else:
                picture = createRGBImage(filepath)
                result = predict_image(tf_model, picture)
                os.remove(picture)
            if '/' in filename:
                filename = filename.split('/')[-1]
            matches = search_for_matches(c, filename, ssdeep_hash, imphash, sha)
            data_tuple = (filename,result[0],
                          int(result[1]*1000)/1000,sha, imphash, ssdeep_hash,
                          datetime.now().strftime("%d %B %Y"), ip, matches)
            query = """INSERT INTO MalDet_S
                           (filename, filetype, type_probability, 
                           sha_1, imphash, ssdeep, analysis_date, analyzer_ip, possible_matches) 
                            VALUES 
                           (?,?,?,?,?,?,?,?,?)"""
            c.execute(query, data_tuple)
        if mode != '2':
            os.remove(filepath)
            conn.commit()
            conn.close()
        if mode == '2':
            # print('Sandbox here!!!')
            subprocess.call(['python3', 'sandbox.py', filepath])
            try:
                with open('result.zip', 'rb') as f:
                    blobData = f.read()
                query = """INSERT INTO MalDet_B
                       (filename, sha1_hash, 
                       result, analysis_date, analyzer_ip) 
                        VALUES 
                       (?,?,?,?,?)"""
                data_tuple_2 = (filename.split('/')[-1], sha, 
                            blobData, datetime.now().strftime("%d %B %Y"), ip)
                c.execute(query, data_tuple_2)
                os.remove(filepath)
                conn.commit()
                conn.close()
            except Exception as e:
                shutil.rmtree('files')
                os.mkdir('files')
        elif mode == '1':
            info = dict()
            info['name'] = data_tuple[0]
            info['type'] = data_tuple[1]
            info['probability'] = int(data_tuple[2]*1000)/1000
            info['sha1'] = data_tuple[3]
            info['imphash'] = data_tuple[4]
            info['ssdeep'] = data_tuple[5]
            info['date'] = data_tuple[6]
            info['source_ip'] = data_tuple[7]
            info['matches'] = data_tuple[8]
            return info
        elif mode == '0':
            info = dict()
            info['name'] = data_tuple[0]
            info['type'] = data_tuple[1]
            return info


def multiple_pack(rows: list, mode: int):
    info = dict()
    names = []
    types = []
    probabilities = []
    sha_1 = []
    imphash_list = []
    ssdeep_list = []
    dates = []
    ips = []
    possible_matches = []
    for row in rows:
        names.append(row[1])
        types.append(row[2])
        probabilities.append(row[3])
        sha_1.append(row[4])
        imphash_list.append(row[5])
        ssdeep_list.append(row[6])
        ips.append(row[7])
        dates.append(row[8])
        possible_matches.append(row[9])
    if mode:
        info['names'] = names
        info['types'] = types
        info['probabilities'] = probabilities
        info['sha1'] = sha_1
        info['imphash'] = imphash_list
        info['ssdeep'] = ssdeep_list
        info['possible matches'] = possible_matches
        info['dates'] = dates
        info['source_ips'] = ips
    else:
        info['names'] = names
        info['types'] = types
    return info


def unit_pack(rows: list, mode: int):
    info = dict()
    name = rows[0][1]
    type_ = rows[0][2]
    probability = rows[0][3]
    sha_1 = rows[0][4]
    imphash = rows[0][5]
    ssdeep_h = rows[0][6]
    ip = rows[0][7]
    date = rows[0][8]
    possible_matches = rows[0][9]
    if mode == '1':
        info['name'] = name
        info['type'] = type_
        info['probability'] = probability
        info['sha1'] = sha_1
        info['imphash'] = imphash
        info['ssdeep'] = ssdeep_h
        info['possible matches'] = possible_matches
        info['date'] = date
        info['source_ip'] = ip
    else:
        info['name'] = name
        info['type'] = type_
    return info


def writeTofile(data, filename):
    with open(filename, 'wb') as file:
        file.write(data)


def readBlob(h: str):
    try:
        conn = sqlite3.connect("MalDet.db")
        c = conn.cursor()
        c.execute("""SELECT result from MalDet_B where
        sha1_hash=?""", (h,))
        rows = c.fetchall()
        if rows:
            for row in rows:
                result = row[0]
        else:
            return 'No such file'
        result_path = "result.zip"
        writeTofile(result, result_path)
        return 'Success'
    except sqlite3.Error as err:
        return err


def build_preflight_response():
    response = make_response()
    response.headers.add("Access-Control-Allow-Origin", "*")
    response.headers.add('Access-Control-Allow-Headers', "*")
    response.headers.add('Access-Control-Allow-Methods', "*")
    return response


def build_actual_response(response):
    response.headers.add("Access-Control-Allow-Origin", "*")
    return response

    
api = Flask(__name__)
#@api.route("/")
#def check_response():
    #ip = request.headers['IP']+' '
    #date = datetime.now().strftime('%H:%M:%S %d/%b/%y')
    #cookie = base64.encodebytes((ip+date).encode()).decode().strip()
    #return jsonify(cookie)


@api.route("/files")
def list_files():
    conn = sqlite3.connect("MalDet.db")
    c = conn.cursor()
    c.execute("""SELECT filename,analysis_date from MalDet_S""")
    rows = c.fetchall()
    return jsonify(rows)


@api.route("/search/<h>", methods=["OPTIONS", "GET"])
def search(h):
    conn = sqlite3.connect("MalDet.db")
    c = conn.cursor()
    if request.method == "OPTIONS":
        return build_preflight_response()
    rows = []
    missing_message = ''
    if request.headers['dynamic_search']:
        if re.match('^[a-f0-9]{40}$', h):
            if os.path.exists('result.zip'):
                os.remove('result.zip')
            msg = readBlob(h)
            if msg == 'Success':
            	return send_file('result.zip', as_attachment=True)
            else:
                return jsonify({'No such file': 'No such sha1 hash in database'})
        else:
            err_msg = 'you can search in dynamic mode only with sha1 value'
            return jsonify({'error': err_msg})
    if request.headers['search_ip']:
        if re.match('^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$', request.headers['search_ip']):
            c.execute("""SELECT * from MalDet_S where analyzer_ip=?""", (request.headers['search_ip'],))
            rows = c.fetchall()
            missing_message = 'such ip address has not analyzed any file yet'
        else:
            return jsonify('invalid ip address')
    elif request.headers['date_date']:
        if re.match('^(0?[1-9]|[12][0-9]|3[01])[\/\-](0?[1-9]|1[012])[\/\-]\d{4}$', request.headers['date_date']):
            date_date = datetime.strptime(request.headers['date_date'], '%d/%m/%Y')
            date = datetime.strftime(date_date, '%d %B %Y')
            c.execute("""SELECT * from MalDet_S where analysis_date=?""", (date,))
            rows = c.fetchall()
            missing_message = 'the system was chilling this day'
        else:
            return jsonify('invalid date format')
    else:
        if re.match('^[a-f0-9]{40}$', h):
            c.execute("""SELECT * from MalDet_S where sha_1=?""", (h,))
            rows = c.fetchall()
            missing_message = 'this file has not been analyzed yet'
        else:
            return jsonify('invalid hash value')
    if rows:
        response = jsonify(multiple_pack(rows, mode='1'))
        return response
#        return build_actual_response(response)
    else:
        response = jsonify(missing_message)
        return response
#        return build_actual_response(response)


# @api.route("/files/<path:path>")
# def get_file(path):
#     """Download a file."""
#     return send_from_directory(UPLOAD_DIRECTORY, path, as_attachment=True)


@api.route("/files/analysis/<mode>", methods=["GET"])
def analysis_from_upload_dir(mode, upload_dir_path=UPLOAD_DIRECTORY):
    analyzed_files = dict()
    files = os.listdir(upload_dir_path)
    for file in files.copy():
        if os.path.isdir(os.path.join(upload_dir_path,file)):
            files.remove(file)
    for file in files:
        ## print(os.path.join(upload_dir_path,file))
        if mode != '2':
            analyzed_files[file] = analysis(filename=os.path.join(upload_dir_path,file),
                                         mode=mode, mfl=True, ip=request.headers['IP'])
        else:
            if os.path.exists('result.zip'):
                os.remove('result.zip')
            analysis(filename=os.path.join(upload_dir_path,file), 
                                         mode=mode, mfl=True, ip=request.headers['IP'])
            shutil.move('result.zip', 'all_results/result_%s.zip' % file)
    for file in files:
        if os.path.exists(os.path.join(upload_dir_path,file)):
            os.remove(os.path.join(upload_dir_path,file))
    if mode != '2':
        return jsonify(analyzed_files)
    else:
        if os.path.exists('all_results.zip'):
            os.remove('all_results.zip')
        shutil.make_archive(f'{CWD}all_results', 'zip', f'{CWD}all_results')
        for file in os.listdir(f'{CWD}all_results/'):
            os.remove(f'{CWD}all_results/'+file)
        return send_file('all_results.zip', as_attachment=True)
        
        
@api.route("/files/<filename>/<mode>", methods=["OPTIONS", "POST"])
def post_file(filename, mode):
    """Upload a file."""
    zip_flag = False
    if request.method == "OPTIONS":
        return build_preflight_response()
    file_data = b''
    data = request.files['file'].read()
    if data[0] == 80 and data[1] == 75 and data[2] == 3 and data[3] == 4:
        zip_flag = True
        with open('tmp.zip', 'wb') as f:
            f.write(data)
        try:
            subprocess.call(["7z", "x", "-pinfected", "-o./tmp", "tmp.zip"])
            os.remove('tmp.zip')
            tmp_file = os.listdir('tmp')[0]
            with open('tmp/'+tmp_file, 'rb') as f:
                file_data = f.read()
            filename = tmp_file
            os.remove('tmp/'+tmp_file)
        except Exception as e:
            err_msg = {"err": "wrong archive password, please use password 'infected'"}
            return jsonify(err_msg)
    if not zip_flag:
        file_data = data
    if mode == '3':
        filepath = os.path.join(UPLOAD_DIRECTORY, filename)
        with open(filepath, "wb") as fp:
            fp.write(file_data)
            return jsonify(f'file {filename} uploaded')
    if mode == '2':
        if os.path.exists("result.zip"):
            os.remove('result.zip')
        filepath = os.path.join(UPLOAD_DIRECTORY, filename)
        try:
            check = pefile.PE(filepath)
        except pefile.PEFormatError:
            err = {'error': 'this is not PE file'}
            return jsonify(err)
        analysis(filename=filename, data=file_data, 
                    mode=mode, ip=request.headers['IP'])
        return send_file('result.zip', as_attachment=True, mimetype="application/zip")
    info = analysis(filename=filename, data=file_data, 
                    mode=mode, ip=request.headers['IP'])
    return jsonify(info)

if __name__ == "__main__":
    api.run(host='0.0.0.0',debug=True, port=8004, use_reloader=False)


