const fs = require('fs-extra');
const path = require('path');
const config = require('../config/config');

class HeuristicAnalyzer {
    constructor() {
        this.sensitivity = config.detection.heuristicSensitivity || 'medium';
        this.suspicionThresholds = {
            low: 60,
            medium: 40,
            high: 25
        };
    }

    /**
     * Analyze file for suspicious characteristics
     * @param {string} filePath - Path to file
     * @param {Object} stats - File stats
     * @returns {Promise<Object|null>} Threat info if suspicious
     */
    async analyze(filePath, stats) {
        let suspicionScore = 0;
        const suspiciousTraits = [];

        const ext = path.extname(filePath).toLowerCase();
        const fileName = path.basename(filePath);

        // Check file extension
        const extScore = this.checkSuspiciousExtension(ext, fileName);
        if (extScore > 0) {
            suspicionScore += extScore;
            suspiciousTraits.push(`Suspicious extension: ${ext}`);
        }

        // Check file name
        const nameScore = this.checkSuspiciousFileName(fileName);
        if (nameScore > 0) {
            suspicionScore += nameScore;
            suspiciousTraits.push('Suspicious file name pattern');
        }

        // Check file location
        const locationScore = this.checkSuspiciousLocation(filePath);
        if (locationScore > 0) {
            suspicionScore += locationScore;
            suspiciousTraits.push('Suspicious file location');
        }

        // Check file size
        const sizeScore = this.checkSuspiciousSize(stats.size, ext);
        if (sizeScore > 0) {
            suspicionScore += sizeScore;
            suspiciousTraits.push('Unusual file size');
        }

        // Check file attributes
        const attrScore = await this.checkFileAttributes(filePath, ext);
        if (attrScore > 0) {
            suspicionScore += attrScore;
            suspiciousTraits.push('Suspicious file attributes');
        }

        // Check for double extensions
        if (this.hasDoubleExtension(fileName)) {
            suspicionScore += 20;
            suspiciousTraits.push('Double extension detected');
        }

        // Check for executable content
        if (await this.hasExecutableContent(filePath, ext)) {
            suspicionScore += 15;
            suspiciousTraits.push('Executable content in non-executable file');
        }

        // Determine if file is suspicious based on threshold
        const threshold = this.suspicionThresholds[this.sensitivity];
        if (suspicionScore >= threshold) {
            return {
                name: 'Heuristic Detection',
                type: 'suspicious',
                severity: suspicionScore >= 70 ? 'high' : suspicionScore >= 50 ? 'medium' : 'low',
                description: `Suspicious file detected (score: ${suspicionScore}). Traits: ${suspiciousTraits.join(', ')}`,
                method: 'heuristic',
                suspicionScore,
                traits: suspiciousTraits
            };
        }

        return null;
    }

    /**
     * Check for suspicious file extensions
     */
    checkSuspiciousExtension(ext, fileName) {
        const highRiskExtensions = [
            '.exe', '.scr', '.pif', '.bat', '.cmd', '.com', '.vbs', '.vbe',
            '.js', '.jse', '.wsf', '.wsh', '.msi', '.jar', '.ps1', '.psm1'
        ];

        const mediumRiskExtensions = [
            '.dll', '.sys', '.drv', '.ocx', '.cpl', '.scf', '.lnk', '.inf',
            '.reg', '.hta', '.gadget', '.application', '.msp', '.mst'
        ];

        if (highRiskExtensions.includes(ext)) {
            return 15;
        }

        if (mediumRiskExtensions.includes(ext)) {
            return 10;
        }

        return 0;
    }

    /**
     * Check for suspicious file name patterns
     */
    checkSuspiciousFileName(fileName) {
        const suspiciousPatterns = [
            /crack/i,
            /keygen/i,
            /patch/i,
            /loader/i,
            /activator/i,
            /setup.*\d+\.exe/i,
            /update.*\d+\.exe/i,
            /invoice.*\.exe/i,
            /document.*\.exe/i,
            /photo.*\.exe/i,
            /video.*\.exe/i,
            /\d{10,}\.exe/i, // Long numeric names
            /^[a-f0-9]{32}/i, // MD5-like names
            /svchost/i,
            /csrss/i,
            /lsass/i,
            /winlogon/i
        ];

        for (const pattern of suspiciousPatterns) {
            if (pattern.test(fileName)) {
                return 20;
            }
        }

        return 0;
    }

    /**
     * Check for suspicious file locations
     */
    checkSuspiciousLocation(filePath) {
        const suspiciousLocations = [
            /\\temp\\/i,
            /\\tmp\\/i,
            /\\appdata\\local\\temp/i,
            /\\downloads\\/i,
            /\\recycler\\/i,
            /\\system32\\/i,
            /\\syswow64\\/i
        ];

        for (const pattern of suspiciousLocations) {
            if (pattern.test(filePath)) {
                return 10;
            }
        }

        return 0;
    }

    /**
     * Check for suspicious file sizes
     */
    checkSuspiciousSize(size, ext) {
        // Very small executables are suspicious
        if (['.exe', '.dll', '.scr'].includes(ext) && size < 10 * 1024) {
            return 15;
        }

        // Very large script files are suspicious
        if (['.bat', '.cmd', '.vbs', '.ps1'].includes(ext) && size > 1024 * 1024) {
            return 10;
        }

        return 0;
    }

    /**
     * Check file attributes for hidden/system flags
     */
    async checkFileAttributes(filePath, ext) {
        try {
            // On Windows, check for hidden and system attributes
            if (process.platform === 'win32') {
                const { execSync } = require('child_process');
                const output = execSync(`attrib "${filePath}"`, { encoding: 'utf8' });

                // Check for hidden (H) and system (S) attributes on executable files
                if (['.exe', '.dll', '.scr', '.bat', '.cmd'].includes(ext)) {
                    if (output.includes('H') || output.includes('S')) {
                        return 15;
                    }
                }
            }
        } catch (error) {
            // Ignore errors
        }

        return 0;
    }

    /**
     * Check for double file extensions
     */
    hasDoubleExtension(fileName) {
        const doubleExtPatterns = [
            /\.pdf\.exe$/i,
            /\.doc\.exe$/i,
            /\.jpg\.exe$/i,
            /\.png\.exe$/i,
            /\.txt\.exe$/i,
            /\.zip\.exe$/i,
            /\.rar\.exe$/i,
            /\.\w+\.(exe|scr|bat|cmd|vbs|js)$/i
        ];

        return doubleExtPatterns.some(pattern => pattern.test(fileName));
    }

    /**
     * Check if non-executable file contains executable content
     */
    async hasExecutableContent(filePath, ext) {
        try {
            // Skip if already an executable
            if (['.exe', '.dll', '.scr', '.com'].includes(ext)) {
                return false;
            }

            // Read first few bytes
            const buffer = Buffer.alloc(512);
            const fd = await fs.open(filePath, 'r');
            await fs.read(fd, buffer, 0, 512, 0);
            await fs.close(fd);

            // Check for MZ header (DOS/PE executable)
            if (buffer[0] === 0x4D && buffer[1] === 0x5A) {
                return true;
            }

            // Check for ELF header (Linux executable)
            if (buffer[0] === 0x7F && buffer[1] === 0x45 && buffer[2] === 0x4C && buffer[3] === 0x46) {
                return true;
            }

            // Check for Mach-O header (macOS executable)
            if ((buffer[0] === 0xFE && buffer[1] === 0xED && buffer[2] === 0xFA) ||
                (buffer[0] === 0xCF && buffer[1] === 0xFA && buffer[2] === 0xED)) {
                return true;
            }

            return false;
        } catch (error) {
            return false;
        }
    }
}

module.exports = HeuristicAnalyzer;
