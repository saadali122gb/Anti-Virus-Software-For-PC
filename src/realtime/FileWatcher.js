const chokidar = require('chokidar');
const { EventEmitter } = require('events');
const config = require('../config/config');
const FileScanner = require('../scanner/FileScanner');
const QuarantineManager = require('../quar/QuarantineManager');
const Logger = require('../utils/Logger');
const Notifications = require('../utils/Notifications');

class FileWatcher extends EventEmitter {
    constructor() {
        super();
        this.logger = new Logger();
        this.scanner = new FileScanner();
        this.quarantine = new QuarantineManager();
        this.watcher = null;
        this.watching = false;
        this.scanQueue = new Set();
        this.processing = false;
    }

    /**
     * Start real-time file monitoring
     */
    start() {
        if (this.watching) {
            this.logger.warn('File watcher already running');
            return;
        }

        const watchPaths = config.watchPaths;

        this.watcher = chokidar.watch(watchPaths, {
            ignored: [
                ...config.exclusions.paths,
                /(^|[\/\\])\../, // Ignore dotfiles
                /node_modules/,
                /\.git/
            ],
            persistent: true,
            ignoreInitial: true,
            awaitWriteFinish: {
                stabilityThreshold: 2000,
                pollInterval: 100
            }
        });

        // File added or modified
        this.watcher.on('add', (filePath) => this.handleFileChange(filePath, 'added'));
        this.watcher.on('change', (filePath) => this.handleFileChange(filePath, 'modified'));

        // Error handling
        this.watcher.on('error', (error) => {
            this.logger.error(`File watcher error: ${error.message}`);
        });

        this.watching = true;
        this.logger.info('Real-time protection started', { paths: watchPaths });
        this.emit('started');

        // Start processing queue
        this.processQueue();
    }

    /**
     * Stop real-time file monitoring
     */
    stop() {
        if (this.watcher) {
            this.watcher.close();
            this.watcher = null;
        }

        this.watching = false;
        this.scanQueue.clear();
        this.logger.info('Real-time protection stopped');
        this.emit('stopped');
    }

    /**
     * Handle file change event
     * @param {string} filePath - Path to changed file
     * @param {string} changeType - Type of change (added, modified)
     */
    handleFileChange(filePath, changeType) {
        // Add to scan queue
        this.scanQueue.add(filePath);
        this.logger.debug(`File ${changeType}: ${filePath}`);
    }

    /**
     * Process scan queue
     */
    async processQueue() {
        while (this.watching) {
            if (this.scanQueue.size > 0 && !this.processing) {
                this.processing = true;

                const filePath = this.scanQueue.values().next().value;
                this.scanQueue.delete(filePath);

                try {
                    await this.scanAndHandle(filePath);
                } catch (error) {
                    this.logger.error(`Queue processing error: ${error.message}`);
                }

                this.processing = false;
            }

            // Wait before checking queue again
            await this.sleep(500);
        }
    }

    /**
     * Scan file and handle threats
     * @param {string} filePath - Path to file
     */
    async scanAndHandle(filePath) {
        try {
            const threat = await this.scanner.scanFile(filePath);

            if (threat) {
                this.logger.warn(`Real-time threat detected: ${threat.name} in ${filePath}`);

                // Show notification
                Notifications.showThreatDetected(threat);

                // Automatically quarantine the threat
                try {
                    await this.quarantine.quarantineFile(filePath);
                    this.logger.info(`Threat automatically quarantined: ${filePath}`);
                    Notifications.showQuarantined(threat.name);

                    this.emit('threat-quarantined', {
                        ...threat,
                        path: filePath
                    });
                } catch (error) {
                    this.logger.error(`Auto-quarantine failed: ${error.message}`);

                    // If quarantine fails, at least notify user
                    this.emit('threat-detected', {
                        ...threat,
                        path: filePath
                    });
                }
            }
        } catch (error) {
            // File might be locked or deleted, ignore
            if (error.code !== 'ENOENT' && error.code !== 'EACCES') {
                this.logger.error(`Scan error for ${filePath}: ${error.message}`);
            }
        }
    }

    /**
     * Sleep utility
     */
    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    /**
     * Get watching status
     */
    isWatching() {
        return this.watching;
    }

    /**
     * Get watched paths
     */
    getWatchedPaths() {
        return config.watchPaths;
    }
}

module.exports = FileWatcher;
