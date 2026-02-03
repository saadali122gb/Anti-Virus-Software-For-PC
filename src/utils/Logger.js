const winston = require('winston');
const path = require('path');
const fs = require('fs-extra');
const config = require('../config/config');

class Logger {
    constructor() {
        // Ensure logs directory exists
        fs.ensureDirSync(config.paths.logs);

        // Create logger instance
        this.logger = winston.createLogger({
            level: config.logging.level,
            format: winston.format.combine(
                winston.format.timestamp({
                    format: 'YYYY-MM-DD HH:mm:ss'
                }),
                winston.format.errors({ stack: true }),
                winston.format.splat(),
                winston.format.json()
            ),
            defaultMeta: { service: 'enterprise-antivirus' },
            transports: [
                // Write all logs to file
                new winston.transports.File({
                    filename: path.join(config.paths.logs, 'error.log'),
                    level: 'error',
                    maxsize: config.logging.maxFileSize,
                    maxFiles: config.logging.maxFiles
                }),
                new winston.transports.File({
                    filename: path.join(config.paths.logs, 'combined.log'),
                    maxsize: config.logging.maxFileSize,
                    maxFiles: config.logging.maxFiles
                })
            ]
        });

        // Also log to console in development
        if (process.env.NODE_ENV !== 'production') {
            this.logger.add(new winston.transports.Console({
                format: winston.format.combine(
                    winston.format.colorize(),
                    winston.format.simple()
                )
            }));
        }
    }

    info(message, meta = {}) {
        this.logger.info(message, meta);
    }

    warn(message, meta = {}) {
        this.logger.warn(message, meta);
    }

    error(message, meta = {}) {
        this.logger.error(message, meta);
    }

    debug(message, meta = {}) {
        this.logger.debug(message, meta);
    }

    // Specific logging methods for antivirus operations
    logScan(scanType, results) {
        this.info('Scan completed', {
            type: scanType,
            filesScanned: results.filesScanned,
            threatsFound: results.threatsFound,
            duration: results.duration
        });
    }

    logThreatDetection(threat) {
        this.warn('Threat detected', {
            name: threat.name,
            path: threat.path,
            type: threat.type,
            severity: threat.severity
        });
    }

    logQuarantine(action, filePath) {
        this.info(`Quarantine ${action}`, { path: filePath });
    }

    logRemoval(filePath, success) {
        this.info('Threat removal', {
            path: filePath,
            success: success
        });
    }
}

module.exports = Logger;
