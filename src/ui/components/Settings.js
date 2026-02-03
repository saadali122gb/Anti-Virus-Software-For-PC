const React = require('react');
const { useState } = React;
const { ipcRenderer } = require('electron');

function Settings({ onNavigate, realtimeProtection, setRealtimeProtection }) {
    const [updating, setUpdating] = useState(false);

    const toggleRealtimeProtection = async () => {
        try {
            const newState = !realtimeProtection;
            await ipcRenderer.invoke('toggle-realtime-protection', newState);
            setRealtimeProtection(newState);
        } catch (error) {
            alert('Failed to toggle protection: ' + error.message);
        }
    };

    const handleUpdateDatabase = async () => {
        setUpdating(true);
        try {
            await ipcRenderer.invoke('update-database');
            alert('Database updated successfully');
        } catch (error) {
            alert('Update failed: ' + error.message);
        } finally {
            setUpdating(false);
        }
    };

    return React.createElement('div', { className: 'settings' },
        React.createElement('div', { className: 'settings-header' },
            React.createElement('h2', null, 'Settings'),
            React.createElement('p', { className: 'subtitle' }, 'Configure antivirus protection')
        ),

        // Real-time Protection
        React.createElement('div', { className: 'settings-section' },
            React.createElement('h3', null, 'Real-time Protection'),
            React.createElement('div', { className: 'setting-item' },
                React.createElement('div', { className: 'setting-info' },
                    React.createElement('div', { className: 'setting-label' }, 'Enable Real-time Protection'),
                    React.createElement('div', { className: 'setting-description' },
                        'Automatically scan files as they are created or modified')
                ),
                React.createElement('label', { className: 'toggle-switch' },
                    React.createElement('input', {
                        type: 'checkbox',
                        checked: realtimeProtection,
                        onChange: toggleRealtimeProtection
                    }),
                    React.createElement('span', { className: 'toggle-slider' })
                )
            )
        ),

        // Database Updates
        React.createElement('div', { className: 'settings-section' },
            React.createElement('h3', null, 'Threat Database'),
            React.createElement('div', { className: 'setting-item' },
                React.createElement('div', { className: 'setting-info' },
                    React.createElement('div', { className: 'setting-label' }, 'Update Virus Definitions'),
                    React.createElement('div', { className: 'setting-description' },
                        'Keep your threat database up to date')
                ),
                React.createElement('button', {
                    className: 'btn-primary',
                    onClick: handleUpdateDatabase,
                    disabled: updating
                }, updating ? 'Updating...' : 'Update Now')
            )
        ),

        // About
        React.createElement('div', { className: 'settings-section' },
            React.createElement('h3', null, 'About'),
            React.createElement('div', { className: 'about-info' },
                React.createElement('div', { className: 'about-item' },
                    React.createElement('span', { className: 'about-label' }, 'Version:'),
                    React.createElement('span', { className: 'about-value' }, '1.0.0')
                ),
                React.createElement('div', { className: 'about-item' },
                    React.createElement('span', { className: 'about-label' }, 'Application:'),
                    React.createElement('span', { className: 'about-value' }, 'Enterprise Antivirus')
                ),
                React.createElement('div', { className: 'about-item' },
                    React.createElement('span', { className: 'about-label' }, 'Company:'),
                    React.createElement('span', { className: 'about-value' }, 'Your Software House')
                )
            )
        )
    );
}

module.exports = Settings;
