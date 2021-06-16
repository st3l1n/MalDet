import React from 'react';

import * as requests from '../requests';


class AnalysisPage extends React.Component {
    state = {
        analyze_mode: 'mode2',
        fileToUpload: undefined,
        isFileUploaded: false,
        analysisResult: undefined,
    };

    onModeChange     = (e) => this.setState({ analyze_mode: e.target.value });
    handleFileUpload = (e) => this.setState({ fileToUpload: e.target.files[0] });

    onUploadButtonClick = () => {
        const isFileUploadedCallback = (result) => {
            console.log('result', result)
            this.setState({ analysisResult: result });
        }

        const formData = new FormData();
        formData.append('file', this.state.fileToUpload);

        requests.uploadFile(
            this.state.analyze_mode,
            this.state.fileToUpload,
            formData,
            isFileUploadedCallback
        );
    };

    render() {
        return (
            <div className="analyze">
                <div className="radio-group">
                    <div className="radio">
                        <input
                            type="radio"
                            value='mode1'
                            onChange={this.onModeChange}
                            checked={this.state.analyze_mode === 'mode1'}
                        />
                        <span>Статический анализ</span>
                    </div>
                    <div className="radio">
                        <input
                            type="radio"
                            value='mode2'
                            onChange={this.onModeChange}
                            checked={this.state.analyze_mode === 'mode2'}
                        />
                        <span>Динамический анализ</span>
                    </div>
                </div>

                <div className="analyze__upload-block">
                    <div className="analyze__upload-buttons">
                        <button
                            className='btn'
                            onClick={() => this.refs.fileInput.click()}
                        >
                            Выбрать файл
                        </button>
                        <input
                            ref="fileInput"
                            onChange={this.handleFileUpload}
                            type="file"
                            style={{ display: "none" }}
                        />

                        <button
                            className="btn"
                            onClick={this.onUploadButtonClick}
                            disabled={this.state.fileToUpload === undefined}
                        >
                            Анализировать
                        </button>
                    </div>
                    <div className="analyze__upload-filename">
                        {this.state.fileToUpload !== undefined && (
                            <React.Fragment>
                                {'Файл '}
                                <span style={{ color: 'blue' }}>
                                    {this.state.fileToUpload.name}
                                </span>
                            </React.Fragment>
                        )}
                    </div>
                </div>

                {this.state.analysisResult !== undefined && (
                    <div className="analyze__body">
                        <pre>
                            {JSON.stringify(this.state.analysisResult, null, 2)}
                        </pre>
                    </div>
                )}
            </div>
        );
    }
};

export default AnalysisPage;