const ThreatDatabase = require('../database/ThreatDatabase');
const fs = require('fs-extra');
const path = require('path');

class SignatureDetector {
    constructor(db) {
        this.db = db || new ThreatDatabase();
        this.signaturesLoaded = false;
        this.signatures = {
            hashes: new Map(),
            patterns: []
        };
    }

    /**
     * Load signatures from database
     */
    async loadSignatures() {
        if (this.signaturesLoaded) return;

        try {
            const hashSignatures = await this.db.getHashSignatures();
            const patternSignatures = await this.db.getPatternSignatures();

            // Load hash signatures
            hashSignatures.forEach(sig => {
                this.signatures.hashes.set(sig.hash.toLowerCase(), {
                    name: sig.name,
                    type: sig.type,
                    severity: sig.severity,
                    description: sig.description
                });
            });

            // Load pattern signatures
            this.signatures.patterns = patternSignatures.map(sig => ({
                name: sig.name,
                type: sig.type,
                severity: sig.severity,
                description: sig.description,
                pattern: new RegExp(sig.pattern, 'gi'),
                offset: sig.offset || 0,
                maxBytes: sig.maxBytes || 1024 * 1024 // Default 1MB
            }));

            this.signaturesLoaded = true;
        } catch (error) {
            console.error('Error loading signatures:', error);
            throw error;
        }
    }

    /**
     * Detect threats using signatures
     * @param {string} filePath - Path to file
     * @param {Object} hashes - File hashes (md5, sha1, sha256)
     * @returns {Promise<Object|null>} Threat info if found
     */
    async detect(filePath, hashes) {
        await this.loadSignatures();

        // Check hash-based signatures
        const hashThreat = this.checkHashSignatures(hashes);
        if (hashThreat) {
            return { ...hashThreat, method: 'signature-hash' };
        }

        // Check pattern-based signatures
        const patternThreat = await this.checkPatternSignatures(filePath);
        if (patternThreat) {
            return { ...patternThreat, method: 'signature-pattern' };
        }

        return null;
    }

    /**
     * Check file hashes against known malware hashes
     * @param {Object} hashes - File hashes
     * @returns {Object|null} Threat info if found
     */
    checkHashSignatures(hashes) {
        // Check MD5
        if (hashes.md5 && this.signatures.hashes.has(hashes.md5.toLowerCase())) {
            return this.signatures.hashes.get(hashes.md5.toLowerCase());
        }

        // Check SHA-1
        if (hashes.sha1 && this.signatures.hashes.has(hashes.sha1.toLowerCase())) {
            return this.signatures.hashes.get(hashes.sha1.toLowerCase());
        }

        // Check SHA-256
        if (hashes.sha256 && this.signatures.hashes.has(hashes.sha256.toLowerCase())) {
            return this.signatures.hashes.get(hashes.sha256.toLowerCase());
        }

        return null;
    }

    /**
     * Check file content against pattern signatures
     * @param {string} filePath - Path to file
     * @returns {Promise<Object|null>} Threat info if found
     */
    async checkPatternSignatures(filePath) {
        try {
            const ext = path.extname(filePath).toLowerCase();

            // Only scan executable and script files for patterns
            const scanExtensions = ['.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', '.scr', '.com'];
            if (!scanExtensions.includes(ext)) {
                return null;
            }

            // Read file content (limited to avoid memory issues)
            const maxReadSize = 5 * 1024 * 1024; // 5MB max
            const stats = await fs.stat(filePath);
            const readSize = Math.min(stats.size, maxReadSize);

            const buffer = Buffer.alloc(readSize);
            const fd = await fs.open(filePath, 'r');
            await fs.read(fd, buffer, 0, readSize, 0);
            await fs.close(fd);

            const content = buffer.toString('binary');

            // Check each pattern signature
            for (const signature of this.signatures.patterns) {
                if (signature.pattern.test(content)) {
                    return {
                        name: signature.name,
                        type: signature.type,
                        severity: signature.severity,
                        description: signature.description
                    };
                }
            }

            return null;
        } catch (error) {
            // File might be locked or inaccessible
            return null;
        }
    }

    /**
     * Check PE (Portable Executable) header for suspicious characteristics
     * @param {string} filePath - Path to file
     * @returns {Promise<Object|null>} Threat info if found
     */
    async checkPEHeader(filePath) {
        try {
            const ext = path.extname(filePath).toLowerCase();
            if (ext !== '.exe' && ext !== '.dll') {
                return null;
            }

            const buffer = Buffer.alloc(1024);
            const fd = await fs.open(filePath, 'r');
            await fs.read(fd, buffer, 0, 1024, 0);
            await fs.close(fd);

            // Check for MZ header (DOS header)
            if (buffer[0] !== 0x4D || buffer[1] !== 0x5A) {
                return null; // Not a valid PE file
            }

            // Get PE header offset
            const peOffset = buffer.readUInt32LE(0x3C);

            // Check for PE signature
            if (buffer[peOffset] === 0x50 && buffer[peOffset + 1] === 0x45) {
                // Valid PE file - could add more sophisticated checks here
                // For now, just return null (no threat detected)
                return null;
            }

            return null;
        } catch (error) {
            return null;
        }
    }
}

module.exports = SignatureDetector;
