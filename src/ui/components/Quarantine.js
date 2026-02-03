const React = require('react');
const { useState, useEffect } = React;
const { ipcRenderer } = require('electron');

function Quarantine({ onNavigate }) {
    const [quarantineList, setQuarantineList] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        loadQuarantineList();
    }, []);

    const loadQuarantineList = async () => {
        setLoading(true);
        try {
            const list = await ipcRenderer.invoke('get-quarantine-list');
            setQuarantineList(list);
        } catch (error) {
            console.error('Failed to load quarantine list:', error);
        } finally {
            setLoading(false);
        }
    };

    const handleRestore = async (quarantineId) => {
        if (!confirm('Are you sure you want to restore this file? It may still be dangerous.')) {
            return;
        }

        try {
            const result = await ipcRenderer.invoke('restore-file', quarantineId);
            alert(`File restored to: ${result.restoredPath}`);
            loadQuarantineList();
        } catch (error) {
            alert('Restore failed: ' + error.message);
        }
    };

    const handleDelete = async (quarantineId) => {
        if (!confirm('Are you sure you want to permanently delete this file? This action cannot be undone.')) {
            return;
        }

        try {
            await ipcRenderer.invoke('delete-quarantine', quarantineId);
            alert('File permanently deleted');
            loadQuarantineList();
        } catch (error) {
            alert('Delete failed: ' + error.message);
        }
    };

    return React.createElement('div', { className: 'quarantine' },
        React.createElement('div', { className: 'quarantine-header' },
            React.createElement('h2', null, 'Quarantine Vault'),
            React.createElement('p', { className: 'subtitle' }, 'Manage isolated threats')
        ),

        loading && React.createElement('div', { className: 'loading' }, 'Loading...'),

        !loading && quarantineList.length === 0 && React.createElement('div', { className: 'empty-state' },
            React.createElement('div', { className: 'empty-icon' }, '🔒'),
            React.createElement('h3', null, 'Quarantine is Empty'),
            React.createElement('p', null, 'No files are currently in quarantine')
        ),

        !loading && quarantineList.length > 0 && React.createElement('div', { className: 'quarantine-list' },
            React.createElement('div', { className: 'list-header' },
                React.createElement('span', null, `${quarantineList.length} file(s) in quarantine`)
            ),
            quarantineList.map((item) =>
                React.createElement('div', { key: item.id, className: 'quarantine-item' },
                    React.createElement('div', { className: 'quarantine-info' },
                        React.createElement('div', { className: 'quarantine-name' },
                            React.createElement('span', { className: 'file-icon' }, '📄'),
                            React.createElement('span', null, item.fileName)
                        ),
                        React.createElement('div', { className: 'quarantine-details' },
                            React.createElement('div', { className: 'detail-item' },
                                React.createElement('span', { className: 'detail-label' }, 'Original Path:'),
                                React.createElement('span', { className: 'detail-value' }, item.originalPath)
                            ),
                            React.createElement('div', { className: 'detail-item' },
                                React.createElement('span', { className: 'detail-label' }, 'Size:'),
                                React.createElement('span', { className: 'detail-value' },
                                    `${(item.fileSize / 1024).toFixed(2)} KB`)
                            ),
                            React.createElement('div', { className: 'detail-item' },
                                React.createElement('span', { className: 'detail-label' }, 'Quarantined:'),
                                React.createElement('span', { className: 'detail-value' },
                                    new Date(item.quarantinedAt).toLocaleString())
                            )
                        )
                    ),
                    React.createElement('div', { className: 'quarantine-actions' },
                        React.createElement('button', {
                            className: 'btn-secondary',
                            onClick: () => handleRestore(item.id)
                        }, 'Restore'),
                        React.createElement('button', {
                            className: 'btn-danger',
                            onClick: () => handleDelete(item.id)
                        }, 'Delete')
                    )
                )
            )
        )
    );
}

module.exports = Quarantine;
