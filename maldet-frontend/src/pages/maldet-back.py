api = Flask(__name__)
@api.route("/")
def check_response():
    ip = request.headers['IP']+' '
    date = datetime.now().strftime('%H:%M:%S %d/%b/%y')
    cookie = base64.encodebytes((ip+date).encode()).decode().strip()
    return jsonify(cookie)


@api.route("/files")
def list_files():
    conn = sqlite3.connect("MalDet.db")
    c = conn.cursor()
    c.execute("""SELECT filename,analysis_date from MalDet_S""")
    rows = c.fetchall()
    return jsonify(rows)


@api.route("/search/<h>")
def search(h):
    conn = sqlite3.connect("MalDet.db")
    c = conn.cursor()
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
        if re.match('^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$', request.h$
            c.execute("""SELECT * from MalDet_S where analyzer_ip=?""", (request.headers['search_ip'],))
            rows = c.fetchall()
            missing_message = 'such ip address has not analyzed any file yet'
        else:
            return jsonify('invalid ip address')
    elif request.headers['date']:
        if re.match('^(0?[1-9]|[12][0-9]|3[01])[\/\-](0?[1-9]|1[012])[\/\-]\d{4}$', request.headers['date']):
            date_date = datetime.strptime(request.headers['date'], '%d/%m/%Y')
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
        return jsonify(multiple_pack(rows, mode='1'))
    else:
        return jsonify(missing_message)


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



@api.route("/files/<filename>/<mode>", methods=["POST"])
def post_file(filename, mode):
    """Upload a file."""
    zip_flag = False
    file_data = b''
    if request.data[0] == 80 and request.data[1] == 75 and request.data[2] == 3 and request.data[3] == 4:
        zip_flag = True
        with open('tmp.zip', 'wb') as f:
            f.write(request.data)
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
        file_data = request.data
    if mode == '3':
        filepath = os.path.join(UPLOAD_DIRECTORY, filename)
        with open(filepath, "wb") as fp:
            fp.write(file_data)
            return jsonify(f'file {filename} uploaded')
    if mode == '2':
        if os.path.exists("result.zip"):
            os.remove('result.zip')
        analysis(filename=filename, data=file_data, 
                    mode=mode, ip=request.headers['IP'])
        return send_file('result.zip', as_attachment=True)
    info = analysis(filename=filename, data=file_data, 
                    mode=mode, ip=request.headers['IP'])
    return jsonify(info)

if __name__ == "__main__":
    api.run(host='0.0.0.0',debug=True, port=8003,use_reloader=False)
