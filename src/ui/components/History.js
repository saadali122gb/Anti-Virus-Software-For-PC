const React = require('react');
const { useState, useEffect } = React;
const { ipcRenderer } = require('electron');

function History({ onNavigate }) {
    const [scanHistory, setScanHistory] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        loadHistory();
    }, []);

    const loadHistory = async () => {
        setLoading(true);
        try {
            const history = await ipcRenderer.invoke('get-scan-history');
            setScanHistory(history);
        } catch (error) {
            console.error('Failed to load history:', error);
        } finally {
            setLoading(false);
        }
    };

    return React.createElement('div', { className: 'history' },
        React.createElement('div', { className: 'history-header' },
            React.createElement('h2', null, 'Scan History'),
            React.createElement('p', { className: 'subtitle' }, 'View past scan results')
        ),

        loading && React.createElement('div', { className: 'loading' }, 'Loading...'),

        !loading && scanHistory.length === 0 && React.createElement('div', { className: 'empty-state' },
            React.createElement('div', { className: 'empty-icon' }, '📜'),
            React.createElement('h3', null, 'No Scan History'),
            React.createElement('p', null, 'Run your first scan to see results here')
        ),

        !loading && scanHistory.length > 0 && React.createElement('div', { className: 'history-list' },
            scanHistory.map((scan) =>
                React.createElement('div', { key: scan.id, className: 'history-item' },
                    React.createElement('div', { className: 'history-header-row' },
                        React.createElement('div', { className: 'scan-type-badge' }, scan.scan_type),
                        React.createElement('div', { className: 'scan-date' },
                            new Date(scan.start_time).toLocaleString())
                    ),
                    React.createElement('div', { className: 'history-stats' },
                        React.createElement('div', { className: 'stat' },
                            React.createElement('span', { className: 'stat-label' }, 'Files Scanned:'),
                            React.createElement('span', { className: 'stat-value' }, scan.files_scanned)
                        ),
                        React.createElement('div', { className: 'stat' },
                            React.createElement('span', { className: 'stat-label' }, 'Threats Found:'),
                            React.createElement('span', {
                                className: `stat-value ${scan.threats_found > 0 ? 'warning' : ''}`
                            }, scan.threats_found)
                        ),
                        React.createElement('div', { className: 'stat' },
                            React.createElement('span', { className: 'stat-label' }, 'Duration:'),
                            React.createElement('span', { className: 'stat-value' },
                                `${Math.round(scan.duration / 1000)}s`)
                        ),
                        React.createElement('div', { className: 'stat' },
                            React.createElement('span', { className: 'stat-label' }, 'Status:'),
                            React.createElement('span', {
                                className: `stat-value status-${scan.status}`
                            }, scan.status)
                        )
                    )
                )
            )
        )
    );
}

module.exports = History;
