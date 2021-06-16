import React from 'react';
import {
    BrowserRouter,
    Switch,
    Route,
    Redirect
} from 'react-router-dom';

import * as Components from './components';
import * as Pages from './pages';

class Router extends React.Component {
    render() {
        return (
            <BrowserRouter>
                <Components.Header />
                <Switch>
                    <Route exact path='/'>
                        <Redirect to={Pages.Routes.AnalysisPageRoute} />
                    </Route>

                    <Route path={Pages.Routes.SearchPageRoute} component={Pages.SearchPage} />
                    <Route path={Pages.Routes.AnalysisPageRoute} component={Pages.AnalysisPage} />
                </Switch>
            </BrowserRouter>
        );
    }
};

export default Router;