const path = require('path');
const os = require('os');

module.exports = {
    // Application paths
    paths: {
        quarantine: path.join(__dirname, '../quarantine'),
        database: path.join(__dirname, '../database/signatures.db'),
        yaraRules: path.join(__dirname, '../database/yara-rules'),
        logs: path.join(__dirname, '../logs')
    },

    // Default scan paths
    scanPaths: {
        quick: [
            path.join(os.homedir(), 'Downloads'),
            path.join(os.homedir(), 'Desktop'),
            path.join(os.homedir(), 'Documents'),
            process.env.TEMP || '/tmp',
            process.env.TMP || '/tmp'
        ],
        full: [
            'C:\\',
            'D:\\',
            'E:\\'
        ],
        critical: [
            'C:\\Windows\\System32',
            'C:\\Windows\\SysWOW64',
            'C:\\Program Files',
            'C:\\Program Files (x86)',
            path.join(os.homedir(), 'AppData\\Roaming'),
            path.join(os.homedir(), 'AppData\\Local')
        ]
    },

    // Real-time protection watch paths
    watchPaths: [
        path.join(os.homedir(), 'Downloads'),
        path.join(os.homedir(), 'Desktop'),
        path.join(os.homedir(), 'Documents'),
        process.env.TEMP || '/tmp'
    ],

    // Scan exclusions
    exclusions: {
        paths: [
            path.join(__dirname, '../quarantine'),
            'C:\\Windows\\WinSxS',
            'C:\\$Recycle.Bin'
        ],
        extensions: [
            '.txt', '.md', '.pdf', '.jpg', '.jpeg', '.png', '.gif', '.bmp',
            '.mp3', '.mp4', '.avi', '.mkv', '.mov'
        ],
        maxFileSize: 500 * 1024 * 1024 // 500MB
    },

    // Performance settings
    performance: {
        maxConcurrentScans: 4,
        chunkSize: 1024 * 1024, // 1MB chunks for reading
        progressUpdateInterval: 100 // ms
    },

    // Threat detection settings
    detection: {
        enableSignatureScanning: true,
        enableHeuristicAnalysis: true,
        enableYaraRules: true,
        heuristicSensitivity: 'medium' // low, medium, high
    },

    // Quarantine settings
    quarantine: {
        encryptionKey: 'CHANGE_THIS_IN_PRODUCTION', // Should be generated and stored securely
        maxQuarantineSize: 5 * 1024 * 1024 * 1024, // 5GB
        autoDeleteAfterDays: 30
    },

    // Update settings
    updates: {
        autoUpdate: true,
        updateInterval: 24 * 60 * 60 * 1000, // 24 hours
        updateServer: 'https://your-update-server.com/signatures'
    },

    // Logging settings
    logging: {
        level: 'info', // error, warn, info, debug
        maxFileSize: 10 * 1024 * 1024, // 10MB
        maxFiles: 5
    },

    // UI settings
    ui: {
        theme: 'dark',
        notifications: true,
        soundAlerts: false
    }
};
