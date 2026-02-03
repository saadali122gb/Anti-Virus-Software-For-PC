const notifier = require('node-notifier');
const path = require('path');

class Notifications {
    /**
     * Show threat detection notification
     * @param {Object} threat - Threat information
     */
    static showThreatDetected(threat) {
        notifier.notify({
            title: '⚠️ Threat Detected',
            message: `${threat.name} found in ${path.basename(threat.path)}`,
            icon: path.join(__dirname, '../../assets/alert-icon.png'),
            sound: true,
            wait: true,
            urgency: 'critical'
        });
    }

    /**
     * Show scan completion notification
     * @param {Object} results - Scan results
     */
    static showScanComplete(results) {
        const message = results.threatsFound > 0
            ? `Found ${results.threatsFound} threat(s) in ${results.filesScanned} files`
            : `No threats found. ${results.filesScanned} files scanned`;

        notifier.notify({
            title: results.threatsFound > 0 ? '⚠️ Scan Complete' : '✅ Scan Complete',
            message: message,
            icon: path.join(__dirname, '../../assets/icon.png'),
            sound: results.threatsFound > 0,
            wait: false
        });
    }

    /**
     * Show quarantine notification
     * @param {string} fileName - Name of quarantined file
     */
    static showQuarantined(fileName) {
        notifier.notify({
            title: '🔒 File Quarantined',
            message: `${fileName} has been isolated`,
            icon: path.join(__dirname, '../../assets/icon.png'),
            sound: false,
            wait: false
        });
    }

    /**
     * Show removal notification
     * @param {string} fileName - Name of removed file
     */
    static showThreatRemoved(fileName) {
        notifier.notify({
            title: '✅ Threat Removed',
            message: `${fileName} has been successfully removed`,
            icon: path.join(__dirname, '../../assets/icon.png'),
            sound: false,
            wait: false
        });
    }

    /**
     * Show database update notification
     */
    static showDatabaseUpdated() {
        notifier.notify({
            title: '🔄 Database Updated',
            message: 'Threat definitions have been updated',
            icon: path.join(__dirname, '../../assets/icon.png'),
            sound: false,
            wait: false
        });
    }

    /**
     * Show real-time protection status notification
     * @param {boolean} enabled - Protection status
     */
    static showProtectionStatus(enabled) {
        notifier.notify({
            title: enabled ? '🛡️ Protection Enabled' : '⚠️ Protection Disabled',
            message: enabled
                ? 'Real-time protection is now active'
                : 'Real-time protection has been disabled',
            icon: path.join(__dirname, '../../assets/icon.png'),
            sound: false,
            wait: false
        });
    }

    /**
     * Show error notification
     * @param {string} message - Error message
     */
    static showError(message) {
        notifier.notify({
            title: '❌ Error',
            message: message,
            icon: path.join(__dirname, '../../assets/alert-icon.png'),
            sound: true,
            wait: false,
            urgency: 'normal'
        });
    }
}

module.exports = Notifications;
