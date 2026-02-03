const React = require('react');
const { useState, useEffect } = React;
const { ipcRenderer } = require('electron');

function Scanner({ onNavigate, scanning, setScanning }) {
    const [scanType, setScanType] = useState('quick');
    const [progress, setProgress] = useState(0);
    const [currentFile, setCurrentFile] = useState('');
    const [threats, setThreats] = useState([]);
    const [results, setResults] = useState(null);

    useEffect(() => {
        // Listen for scan progress
        ipcRenderer.on('scan-progress', (event, data) => {
            setProgress(data.percentage);
            setCurrentFile(data.currentFile);
        });

        // Listen for threat detection
        ipcRenderer.on('threat-detected', (event, threat) => {
            setThreats(prev => [...prev, threat]);
        });

        return () => {
            ipcRenderer.removeAllListeners('scan-progress');
            ipcRenderer.removeAllListeners('threat-detected');
        };
    }, []);

    const startScan = async () => {
        setScanning(true);
        setProgress(0);
        setThreats([]);
        setResults(null);
        setCurrentFile('');

        try {
            const scanResults = await ipcRenderer.invoke('start-scan', {
                type: scanType
            });

            setResults(scanResults);
        } catch (error) {
            console.error('Scan error:', error);
            alert('Scan failed: ' + error.message);
        } finally {
            setScanning(false);
        }
    };

    const handleQuarantine = async (threatPath) => {
        try {
            await ipcRenderer.invoke('quarantine-file', threatPath);
            alert('File quarantined successfully');
            // Remove from threats list
            setThreats(prev => prev.filter(t => t.path !== threatPath));
        } catch (error) {
            alert('Quarantine failed: ' + error.message);
        }
    };

    const handleRemove = async (threatPath) => {
        if (!confirm('Are you sure you want to permanently delete this file?')) {
            return;
        }

        try {
            await ipcRenderer.invoke('remove-threat', threatPath);
            alert('Threat removed successfully');
            // Remove from threats list
            setThreats(prev => prev.filter(t => t.path !== threatPath));
        } catch (error) {
            alert('Removal failed: ' + error.message);
        }
    };

    return React.createElement('div', { className: 'scanner' },
        React.createElement('div', { className: 'scanner-header' },
            React.createElement('h2', null, 'System Scanner'),
            React.createElement('p', { className: 'subtitle' }, 'Scan your system for malware and threats')
        ),

        // Scan Type Selection
        !scanning && !results && React.createElement('div', { className: 'scan-options' },
            React.createElement('h3', null, 'Select Scan Type'),
            React.createElement('div', { className: 'scan-types' },
                React.createElement('div', {
                    className: `scan-type-card ${scanType === 'quick' ? 'selected' : ''}`,
                    onClick: () => setScanType('quick')
                },
                    React.createElement('div', { className: 'scan-type-icon' }, '⚡'),
                    React.createElement('h4', null, 'Quick Scan'),
                    React.createElement('p', null, 'Scan common locations (Downloads, Desktop, Temp)')
                ),
                React.createElement('div', {
                    className: `scan-type-card ${scanType === 'full' ? 'selected' : ''}`,
                    onClick: () => setScanType('full')
                },
                    React.createElement('div', { className: 'scan-type-icon' }, '🔍'),
                    React.createElement('h4', null, 'Full Scan'),
                    React.createElement('p', null, 'Deep scan of all drives (may take longer)')
                )
            ),
            React.createElement('button', {
                className: 'btn-primary btn-large',
                onClick: startScan
            }, 'Start Scan')
        ),

        // Scanning Progress
        scanning && React.createElement('div', { className: 'scan-progress' },
            React.createElement('div', { className: 'progress-header' },
                React.createElement('h3', null, 'Scanning...'),
                React.createElement('span', { className: 'progress-percentage' }, `${progress}%`)
            ),
            React.createElement('div', { className: 'progress-bar' },
                React.createElement('div', {
                    className: 'progress-fill',
                    style: { width: `${progress}%` }
                })
            ),
            React.createElement('div', { className: 'current-file' },
                React.createElement('span', null, 'Scanning: '),
                React.createElement('span', { className: 'file-path' }, currentFile)
            ),
            threats.length > 0 && React.createElement('div', { className: 'threats-found' },
                React.createElement('h4', null, `⚠️ ${threats.length} Threat(s) Detected`),
                React.createElement('div', { className: 'threats-list' },
                    threats.map((threat, index) =>
                        React.createElement('div', { key: index, className: 'threat-item-compact' },
                            React.createElement('span', { className: 'threat-name' }, threat.name),
                            React.createElement('span', { className: 'threat-path' }, threat.path)
                        )
                    )
                )
            )
        ),

        // Scan Results
        results && React.createElement('div', { className: 'scan-results' },
            React.createElement('div', { className: 'results-header' },
                React.createElement('div', {
                    className: `results-icon ${results.threatsFound > 0 ? 'warning' : 'success'}`
                }, results.threatsFound > 0 ? '⚠️' : '✓'),
                React.createElement('h3', null, results.threatsFound > 0
                    ? `${results.threatsFound} Threat(s) Found`
                    : 'No Threats Found'),
                React.createElement('p', null, `Scanned ${results.filesScanned} files in ${Math.round(results.duration / 1000)}s`)
            ),

            threats.length > 0 && React.createElement('div', { className: 'threats-details' },
                React.createElement('h4', null, 'Detected Threats'),
                threats.map((threat, index) =>
                    React.createElement('div', { key: index, className: 'threat-card' },
                        React.createElement('div', { className: 'threat-info' },
                            React.createElement('div', { className: 'threat-header' },
                                React.createElement('span', { className: 'threat-name' }, threat.name),
                                React.createElement('span', {
                                    className: `threat-severity ${threat.severity}`
                                }, threat.severity)
                            ),
                            React.createElement('div', { className: 'threat-path' }, threat.path),
                            React.createElement('div', { className: 'threat-description' }, threat.description)
                        ),
                        React.createElement('div', { className: 'threat-actions' },
                            React.createElement('button', {
                                className: 'btn-secondary',
                                onClick: () => handleQuarantine(threat.path)
                            }, 'Quarantine'),
                            React.createElement('button', {
                                className: 'btn-danger',
                                onClick: () => handleRemove(threat.path)
                            }, 'Delete')
                        )
                    )
                )
            ),

            React.createElement('button', {
                className: 'btn-primary',
                onClick: () => {
                    setResults(null);
                    setThreats([]);
                }
            }, 'New Scan')
        )
    );
}

module.exports = Scanner;
