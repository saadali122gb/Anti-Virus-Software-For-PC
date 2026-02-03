const React = require('react');
const { useState, useEffect } = React;
const { ipcRenderer } = require('electron');

function Dashboard({ onNavigate, realtimeProtection }) {
    const [stats, setStats] = useState({
        totalScans: 0,
        totalThreats: 0,
        recentThreats: [],
        threatsByType: []
    });
    const [lastScan, setLastScan] = useState(null);

    useEffect(() => {
        loadStatistics();
        loadScanHistory();
    }, []);

    const loadStatistics = async () => {
        try {
            const statistics = await ipcRenderer.invoke('get-statistics');
            setStats(statistics);
        } catch (error) {
            console.error('Failed to load statistics:', error);
        }
    };

    const loadScanHistory = async () => {
        try {
            const history = await ipcRenderer.invoke('get-scan-history');
            if (history && history.length > 0) {
                setLastScan(history[0]);
            }
        } catch (error) {
            console.error('Failed to load scan history:', error);
        }
    };

    const handleQuickScan = () => {
        onNavigate('scanner');
    };

    return React.createElement('div', { className: 'dashboard' },
        React.createElement('div', { className: 'dashboard-header' },
            React.createElement('h2', null, 'Security Dashboard'),
            React.createElement('p', { className: 'subtitle' }, 'System protection overview')
        ),

        // Protection Status Card
        React.createElement('div', { className: 'status-card' },
            React.createElement('div', { className: 'status-card-header' },
                React.createElement('div', {
                    className: `status-icon ${realtimeProtection ? 'protected' : 'at-risk'}`
                }, realtimeProtection ? '✓' : '⚠'),
                React.createElement('div', null,
                    React.createElement('h3', null, realtimeProtection ? 'System Protected' : 'Protection Disabled'),
                    React.createElement('p', null, realtimeProtection
                        ? 'Real-time protection is active'
                        : 'Enable real-time protection in settings')
                )
            ),
            React.createElement('button', {
                className: 'btn-primary',
                onClick: handleQuickScan
            }, 'Run Quick Scan')
        ),

        // Statistics Grid
        React.createElement('div', { className: 'stats-grid' },
            React.createElement('div', { className: 'stat-card' },
                React.createElement('div', { className: 'stat-icon' }, '🔍'),
                React.createElement('div', { className: 'stat-content' },
                    React.createElement('div', { className: 'stat-value' }, stats.totalScans),
                    React.createElement('div', { className: 'stat-label' }, 'Total Scans')
                )
            ),
            React.createElement('div', { className: 'stat-card' },
                React.createElement('div', { className: 'stat-icon' }, '⚠️'),
                React.createElement('div', { className: 'stat-content' },
                    React.createElement('div', { className: 'stat-value' }, stats.totalThreats),
                    React.createElement('div', { className: 'stat-label' }, 'Threats Detected')
                )
            ),
            React.createElement('div', { className: 'stat-card' },
                React.createElement('div', { className: 'stat-icon' }, '🔒'),
                React.createElement('div', { className: 'stat-content' },
                    React.createElement('div', { className: 'stat-value' }, stats.recentThreats.length),
                    React.createElement('div', { className: 'stat-label' }, 'Quarantined')
                )
            )
        ),

        // Last Scan Info
        lastScan && React.createElement('div', { className: 'info-card' },
            React.createElement('h3', null, 'Last Scan'),
            React.createElement('div', { className: 'info-grid' },
                React.createElement('div', { className: 'info-item' },
                    React.createElement('span', { className: 'info-label' }, 'Type:'),
                    React.createElement('span', { className: 'info-value' }, lastScan.scan_type)
                ),
                React.createElement('div', { className: 'info-item' },
                    React.createElement('span', { className: 'info-label' }, 'Files Scanned:'),
                    React.createElement('span', { className: 'info-value' }, lastScan.files_scanned)
                ),
                React.createElement('div', { className: 'info-item' },
                    React.createElement('span', { className: 'info-label' }, 'Threats Found:'),
                    React.createElement('span', { className: 'info-value' }, lastScan.threats_found)
                ),
                React.createElement('div', { className: 'info-item' },
                    React.createElement('span', { className: 'info-label' }, 'Date:'),
                    React.createElement('span', { className: 'info-value' },
                        new Date(lastScan.start_time).toLocaleString())
                )
            )
        ),

        // Recent Threats
        stats.recentThreats.length > 0 && React.createElement('div', { className: 'info-card' },
            React.createElement('h3', null, 'Recent Threats'),
            React.createElement('div', { className: 'threats-list' },
                stats.recentThreats.slice(0, 5).map((threat, index) =>
                    React.createElement('div', { key: index, className: 'threat-item' },
                        React.createElement('div', { className: 'threat-name' }, threat.threat_name),
                        React.createElement('div', { className: 'threat-path' }, threat.file_path),
                        React.createElement('div', {
                            className: `threat-severity ${threat.severity}`
                        }, threat.severity)
                    )
                )
            )
        )
    );
}

module.exports = Dashboard;
