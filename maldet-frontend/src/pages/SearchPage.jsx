import React from 'react';

import * as requests from '../requests';

import './Pages.scss';


class SearchPage extends React.Component {
    state = {
        input: '',
        fetchedData: undefined,
        search_mode: 'dynamic_search'
    };

    onSearchInputChange = (e) => this.setState({ input: e.target.value });
    onModeChange        = (e) => this.setState({ search_mode: e.target.value });

    onSearchButtonClick = async (e) => {
        const setDataCallback = (response) => this.setState({ fetchedData: response });

        const collectedData = {
            search_mode: this.state.search_mode,
            input_data: this.state.input
        };

        await requests.searchData(collectedData, setDataCallback);
    };

    render() {
        return (
            <div className="search">
                <div className="radio-group">
                    <div className="radio">
                        <input
                            type="radio"
                            value='dynamic_search'
                            onChange={this.onModeChange}
                            checked={this.state.search_mode === 'dynamic_search'}
                        />
                        <span>Поиск результатов динамического анализа</span>
                    </div>

                    <div className="radio">
                        <input
                            type="radio"
                            value='search_ip'
                            onChange={this.onModeChange}
                            checked={this.state.search_mode === 'search_ip'}
                        />
                        <span>Поиск по IP адресу</span>
                    </div>

                    <div className="radio">
                        <input
                            type="radio"
                            value='date'
                            onChange={this.onModeChange}
                            checked={this.state.search_mode === 'date'}
                        />
                        <span>Поиск по дате в формате `дд/мм/гггг`</span>
                    </div>

                    <div className="radio">
                        <input
                            type="radio"
                            value='hash'
                            onChange={this.onModeChange}
                            checked={this.state.search_mode === 'hash'}
                        />
                        <span>Поиск по значению sha1</span>
                    </div>
                </div>

                <div className="search__input-block">
                    <input
                        type={'text'}
                        placeholder={'Введите текст для поиска: ...'}
                        className={'search__input'}
                        onChange={this.onSearchInputChange}
                    />
                    <button
                        onClick={this.onSearchButtonClick}
                        className="btn"
                        disabled={this.state.input === ''}
                    >
                        Найти
                    </button>
                </div>
                {this.state.fetchedData && (
                    <div className="search__body">
                        <pre>
                            {JSON.stringify(this.state.fetchedData, null, 2)}
                        </pre>
                    </div>
                )}
            </div>
        );
    }
};

export default SearchPage;
