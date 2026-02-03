const React = require('react');
const { useState, useEffect } = React;
const { ipcRenderer } = require('electron');
const Dashboard = require('./components/Dashboard');
const Scanner = require('./components/Scanner');
const Quarantine = require('./components/Quarantine');
const History = require('./components/History');
const Settings = require('./components/Settings');

function App() {
    const [currentView, setCurrentView] = useState('dashboard');
    const [realtimeProtection, setRealtimeProtection] = useState(true);
    const [scanning, setScanning] = useState(false);

    useEffect(() => {
        // Listen for real-time protection status changes
        ipcRenderer.on('realtime-status-changed', (event, enabled) => {
            setRealtimeProtection(enabled);
        });

        // Listen for quick scan trigger from tray
        ipcRenderer.on('start-quick-scan', () => {
            setCurrentView('scanner');
        });

        return () => {
            ipcRenderer.removeAllListeners('realtime-status-changed');
            ipcRenderer.removeAllListeners('start-quick-scan');
        };
    }, []);

    const renderView = () => {
        switch (currentView) {
            case 'dashboard':
                return React.createElement(Dashboard, {
                    onNavigate: setCurrentView,
                    realtimeProtection
                });
            case 'scanner':
                return React.createElement(Scanner, {
                    onNavigate: setCurrentView,
                    scanning,
                    setScanning
                });
            case 'quarantine':
                return React.createElement(Quarantine, {
                    onNavigate: setCurrentView
                });
            case 'history':
                return React.createElement(History, {
                    onNavigate: setCurrentView
                });
            case 'settings':
                return React.createElement(Settings, {
                    onNavigate: setCurrentView,
                    realtimeProtection,
                    setRealtimeProtection
                });
            default:
                return React.createElement(Dashboard, {
                    onNavigate: setCurrentView,
                    realtimeProtection
                });
        }
    };

    return React.createElement('div', { className: 'app' },
        // Sidebar
        React.createElement('div', { className: 'sidebar' },
            React.createElement('div', { className: 'logo' },
                React.createElement('div', { className: 'logo-icon' }, '🛡️'),
                React.createElement('h1', null, 'Enterprise AV')
            ),
            React.createElement('nav', { className: 'nav' },
                React.createElement('button', {
                    className: `nav-item ${currentView === 'dashboard' ? 'active' : ''}`,
                    onClick: () => setCurrentView('dashboard')
                },
                    React.createElement('span', { className: 'nav-icon' }, '📊'),
                    React.createElement('span', null, 'Dashboard')
                ),
                React.createElement('button', {
                    className: `nav-item ${currentView === 'scanner' ? 'active' : ''}`,
                    onClick: () => setCurrentView('scanner')
                },
                    React.createElement('span', { className: 'nav-icon' }, '🔍'),
                    React.createElement('span', null, 'Scanner')
                ),
                React.createElement('button', {
                    className: `nav-item ${currentView === 'quarantine' ? 'active' : ''}`,
                    onClick: () => setCurrentView('quarantine')
                },
                    React.createElement('span', { className: 'nav-icon' }, '🔒'),
                    React.createElement('span', null, 'Quarantine')
                ),
                React.createElement('button', {
                    className: `nav-item ${currentView === 'history' ? 'active' : ''}`,
                    onClick: () => setCurrentView('history')
                },
                    React.createElement('span', { className: 'nav-icon' }, '📜'),
                    React.createElement('span', null, 'History')
                ),
                React.createElement('button', {
                    className: `nav-item ${currentView === 'settings' ? 'active' : ''}`,
                    onClick: () => setCurrentView('settings')
                },
                    React.createElement('span', { className: 'nav-icon' }, '⚙️'),
                    React.createElement('span', null, 'Settings')
                )
            ),
            React.createElement('div', { className: 'sidebar-footer' },
                React.createElement('div', { className: 'protection-status' },
                    React.createElement('div', {
                        className: `status-indicator ${realtimeProtection ? 'active' : 'inactive'}`
                    }),
                    React.createElement('span', null, realtimeProtection ? 'Protected' : 'At Risk')
                )
            )
        ),
        // Main content
        React.createElement('div', { className: 'main-content' },
            renderView()
        )
    );
}

module.exports = App;
