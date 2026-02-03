const fs = require('fs-extra');
const path = require('path');
const { EventEmitter } = require('events');
const { glob } = require('glob');
const config = require('../config/config');
const HashGenerator = require('../utils/HashGenerator');
const SignatureDetector = require('./SignatureDetector');
const HeuristicAnalyzer = require('./HeuristicAnalyzer');
const Logger = require('../utils/Logger');
const ThreatDatabase = require('../database/ThreatDatabase');

class FileScanner extends EventEmitter {
    constructor() {
        super();
        this.logger = new Logger();
        this.db = new ThreatDatabase();
        this.signatureDetector = new SignatureDetector(this.db);
        this.heuristicAnalyzer = new HeuristicAnalyzer();
        this.scanning = false;
        this.paused = false;
        this.stats = {
            filesScanned: 0,
            threatsFound: 0,
            errors: 0,
            startTime: null,
            endTime: null,
            threats: []
        };
    }

    /**
     * Start a scan with specified options
     * @param {Object} options - Scan options
     * @returns {Promise<Object>} Scan results
     */
    async scan(options = {}) {
        const {
            type = 'quick', // quick, full, custom
            paths = [],
            deep = true
        } = options;

        this.scanning = true;
        await this.db.initialize();
        this.scanId = await this.db.recordScanStart(type);
        this.stats = {
            filesScanned: 0,
            threatsFound: 0,
            errors: 0,
            startTime: Date.now(),
            endTime: null,
            threats: []
        };

        try {
            let scanPaths = [];

            // Determine scan paths based on type
            if (type === 'quick') {
                scanPaths = config.scanPaths.quick;
            } else if (type === 'full') {
                scanPaths = config.scanPaths.full;
            } else if (type === 'custom' && paths.length > 0) {
                scanPaths = paths;
            } else {
                throw new Error('Invalid scan type or paths');
            }

            this.logger.info(`Starting ${type} scan`, { paths: scanPaths });

            // Collect all files to scan
            const filesToScan = await this.collectFiles(scanPaths, deep);
            const totalFiles = filesToScan.length;

            this.logger.info(`Found ${totalFiles} files to scan`);
            console.log(`[FileScanner] Found ${totalFiles} files to scan`);
            this.emit('scan-started', { totalFiles, type });

            // Scan files
            for (let i = 0; i < filesToScan.length; i++) {
                if (!this.scanning) break;

                while (this.paused) {
                    await this.sleep(100);
                }

                const filePath = filesToScan[i];

                try {
                    await this.scanFile(filePath);
                    this.stats.filesScanned++;

                    // Emit progress update
                    if (this.stats.filesScanned % 10 === 0 || this.stats.filesScanned === totalFiles) {
                        this.emit('progress', {
                            filesScanned: this.stats.filesScanned,
                            totalFiles: totalFiles,
                            percentage: Math.round((this.stats.filesScanned / totalFiles) * 100),
                            currentFile: filePath,
                            threatsFound: this.stats.threatsFound
                        });
                    }
                } catch (error) {
                    this.stats.errors++;
                    this.logger.error(`Error scanning file: ${filePath}`, { error: error.message });
                }
            }

            this.stats.endTime = Date.now();
            this.stats.duration = this.stats.endTime - this.stats.startTime;

            await this.db.recordScanComplete(
                this.scanId,
                this.stats.filesScanned,
                this.stats.threatsFound,
                this.stats.duration
            );

            this.logger.logScan(type, this.stats);
            this.emit('scan-complete', this.stats);

            return this.stats;
        } catch (error) {
            this.logger.error('Scan error', { error: error.message });
            throw error;
        } finally {
            this.scanning = false;
        }
    }

    /**
     * Scan a single file for threats
     * @param {string} filePath - Path to file
     * @returns {Promise<Object|null>} Threat info if found
     */
    async scanFile(filePath) {
        try {
            await this.db.initialize();
            // Check if file exists and is accessible
            const stats = await fs.stat(filePath);

            // Skip if file is too large
            if (stats.size > config.exclusions.maxFileSize) {
                return null;
            }

            // Skip directories
            if (stats.isDirectory()) {
                return null;
            }

            // Check exclusions
            if (this.isExcluded(filePath)) {
                return null;
            }

            // Generate file hashes
            const hashes = await HashGenerator.generateAllHashes(filePath);

            // Signature-based detection
            if (config.detection.enableSignatureScanning) {
                const signatureThreat = await this.signatureDetector.detect(filePath, hashes);
                if (signatureThreat) {
                    return this.handleThreatFound(filePath, signatureThreat, stats);
                }
            }

            // Heuristic analysis
            if (config.detection.enableHeuristicAnalysis) {
                const heuristicThreat = await this.heuristicAnalyzer.analyze(filePath, stats);
                if (heuristicThreat) {
                    return this.handleThreatFound(filePath, heuristicThreat, stats);
                }
            }

            return null;
        } catch (error) {
            // File might be locked or inaccessible
            if (error.code !== 'ENOENT' && error.code !== 'EACCES') {
                throw error;
            }
            return null;
        }
    }

    /**
     * Handle when a threat is found
     * @param {string} filePath - Path to infected file
     * @param {Object} threatInfo - Threat information
     * @param {Object} stats - File stats
     */
    handleThreatFound(filePath, threatInfo, stats) {
        const threat = {
            path: filePath,
            name: threatInfo.name,
            type: threatInfo.type,
            severity: threatInfo.severity,
            description: threatInfo.description,
            detectionMethod: threatInfo.method,
            fileSize: stats.size,
            detectedAt: new Date().toISOString()
        };

        this.stats.threatsFound++;
        this.stats.threats.push(threat);

        // Record threat in database asynchronously
        this.db.recordThreatDetection(
            this.scanId,
            threat.path,
            threat.name,
            threat.type,
            threat.severity,
            threat.detectionMethod
        ).catch(err => this.logger.error('Failed to record threat', { error: err.message }));

        this.logger.logThreatDetection(threat);
        this.emit('threat-found', threat);

        return threat;
    }

    /**
     * Collect all files from specified paths
     * @param {Array} paths - Paths to scan
     * @param {boolean} deep - Deep scan subdirectories
     * @returns {Promise<Array>} Array of file paths
     */
    async collectFiles(paths, deep = true) {
        const files = [];

        for (const scanPath of paths) {
            try {
                if (!await fs.pathExists(scanPath)) {
                    continue;
                }

                const pattern = deep ? '**/*' : '*';
                // Glob expects forward slashes
                const normalizedScanPath = scanPath.replace(/\\/g, '/');
                const globPattern = `${normalizedScanPath}/${pattern}`;

                const foundFiles = await glob(globPattern, {
                    nodir: true,
                    follow: false,
                    ignore: config.exclusions.paths.map(p => p.replace(/\\/g, '/'))
                });

                // Convert back to OS-specific paths
                const normalizedFiles = foundFiles.map(f => path.normalize(f));
                console.log(`[FileScanner] Collected ${normalizedFiles.length} files from ${scanPath}`);
                files.push(...normalizedFiles);
            } catch (error) {
                this.logger.error(`Error collecting files from ${scanPath}`, { error: error.message });
            }
        }

        return files;
    }

    /**
     * Check if file should be excluded from scan
     * @param {string} filePath - File path
     * @returns {boolean} True if excluded
     */
    isExcluded(filePath) {
        const ext = path.extname(filePath).toLowerCase();

        // Check extension exclusions
        if (config.exclusions.extensions.includes(ext)) {
            return true;
        }

        // Check path exclusions
        for (const excludedPath of config.exclusions.paths) {
            if (filePath.startsWith(excludedPath)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Pause the scan
     */
    pause() {
        this.paused = true;
        this.emit('scan-paused');
    }

    /**
     * Resume the scan
     */
    resume() {
        this.paused = false;
        this.emit('scan-resumed');
    }

    /**
     * Stop the scan
     */
    stop() {
        this.scanning = false;
        this.emit('scan-stopped');
    }

    /**
     * Sleep utility
     */
    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

module.exports = FileScanner;
