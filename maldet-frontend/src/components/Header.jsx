import React from 'react';
import { Link } from 'react-router-dom';

import { Routes } from '../pages';

import './Header.scss';

class Header extends React.Component {
    render() {
        return (
            <header className="header">
                <Link to={Routes.AnalysisPageRoute} className='header__item'>
                    Анализ
                </Link>

                <Link to={Routes.SearchPageRoute} className='header__item'>
                    Поиск
                </Link>
            </header>
        );
    }
};

export default Header;