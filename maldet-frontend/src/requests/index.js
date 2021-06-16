import * as axios from 'axios';

const FileDownload = require('js-file-download');

const baseUrl = 'http://10.33.100.113:8004';


export const searchData = async (data, callback) => {
    const search_mode = data.search_mode;

    const url = search_mode === 'hash' || search_mode === 'dynamic_search'
        ? baseUrl + '/search/' + data.input_data
        : baseUrl + '/search/' + data.search_mode;

    if (search_mode === 'hash') {
        axios(url, {
            method: 'GET',
            headers: {
                'dynamic_search': '',
                'search_ip': '',
                'date_date': ''
            }
        })
            .then(resp => callback(resp.data))
            .catch(err => callback(err))
    }

    else if (search_mode === 'date') {
        axios(url, {
            method: 'GET',
            headers: {
                'dynamic_search': '',
                'search_ip': '',
                'date_date': data.input_data
            }
        })
            .then(resp => callback(resp.data))
            .catch(err => callback(err));
    }

    else if (search_mode === 'search_ip') {
        axios(url, {
            method: 'GET',
            headers: {
                'dynamic_search': '',
                'search_ip': data.input_data,
                'date_date': ''
            }
        })
            .then(resp => callback(resp.data))
            .catch(err => callback(err));
    }

    // done
    else if (search_mode === 'dynamic_search') {
        axios(url, {
            method: 'GET',
            headers: {
                'dynamic_search': 'True',
                'responseType': 'arraybuffer',
                'Content-Type': "application/octet-stream",
                'Content-Disposition': "attachment;filename=result.zip"
            }, responseType: 'blob'
        })
            .then(resp => {
                FileDownload(resp.data, 'result.zip');
                callback('Отчет успешно скачан');
            })
            .catch(err => callback(err));
    }
};


export const uploadFile = (mode, fileToUpload, data, callback) => {
    const requestMode = mode === 'mode1' ? '1' : '2';
    const url = `${baseUrl}/files/${fileToUpload.name}/${requestMode}`;
    
    if (requestMode === '1'){
        axios.post(url, data, {
            headers: {
                "Content-Type": "multiform/data",
                'dynamic_search': '',
                'search_ip': '',
                'date_date': '',
                'IP': '127.0.0.1'
            }
        })
            .then(res => {
                    callback(res.data)
            })
            .catch(err => console.log(err));
    }
    else {
        axios.post(url, data, {
            headers: {
                "Content-Type": "multiform/data",
                'dynamic_search': '',
                'search_ip': '',
                'date_date': '',
                'IP': '127.0.0.1'
            }, 
            responseType: 'blob'
        })
            .then(res => {
                FileDownload(res.data, `${fileToUpload.name}__result.zip`, "application/octet-stream");
                callback('Отчет успешно скачан');
                
            })
            .catch(err => console.log(err));
    }
    // axios.post(url, data, {
    //     headers: {
    //         "Content-Type": "multiform/data",
    //         'dynamic_search': '',
    //         'search_ip': '',
    //         'date_date': '',
    //         'IP': '127.0.0.1'
    //     }, 
    //     responseType: 'blob'
    // })
    //     .then(res => {
    //         if (requestMode === '1')
    //             callback(res.data)
    //         else {
    //             // console.log('resp.data', res.data);
    //             FileDownload(res.data, `${fileToUpload.name}__result.zip`, "application/octet-stream");
    //             // res.data.pipe(fs.createWriteStream('result.zip'))
    //             callback('Отчет успешно скачан');
    //         }
    //     })
    //     .catch(err => console.log(err));
};
