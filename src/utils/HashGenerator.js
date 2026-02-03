const crypto = require('crypto');
const fs = require('fs');
const stream = require('stream');
const { promisify } = require('util');

const pipeline = promisify(stream.pipeline);

class HashGenerator {
    /**
     * Generate MD5 hash of a file
     * @param {string} filePath - Path to the file
     * @returns {Promise<string>} MD5 hash
     */
    static async generateMD5(filePath) {
        return this.generateHash(filePath, 'md5');
    }

    /**
     * Generate SHA-256 hash of a file
     * @param {string} filePath - Path to the file
     * @returns {Promise<string>} SHA-256 hash
     */
    static async generateSHA256(filePath) {
        return this.generateHash(filePath, 'sha256');
    }

    /**
     * Generate SHA-1 hash of a file
     * @param {string} filePath - Path to the file
     * @returns {Promise<string>} SHA-1 hash
     */
    static async generateSHA1(filePath) {
        return this.generateHash(filePath, 'sha1');
    }

    /**
     * Generate hash of a file using specified algorithm
     * @param {string} filePath - Path to the file
     * @param {string} algorithm - Hash algorithm (md5, sha1, sha256, etc.)
     * @returns {Promise<string>} File hash
     */
    static async generateHash(filePath, algorithm = 'sha256') {
        return new Promise((resolve, reject) => {
            const hash = crypto.createHash(algorithm);
            const fileStream = fs.createReadStream(filePath);

            fileStream.on('error', (err) => {
                reject(err);
            });

            fileStream.on('data', (chunk) => {
                hash.update(chunk);
            });

            fileStream.on('end', () => {
                resolve(hash.digest('hex'));
            });
        });
    }

    /**
     * Generate multiple hashes for a file by reading it only once
     * @param {string} filePath - Path to the file
     * @returns {Promise<Object>} Object containing md5, sha1, and sha256 hashes
     */
    static async generateAllHashes(filePath) {
        return new Promise((resolve, reject) => {
            const md5 = crypto.createHash('md5');
            const sha1 = crypto.createHash('sha1');
            const sha256 = crypto.createHash('sha256');

            const fileStream = fs.createReadStream(filePath);

            fileStream.on('error', (err) => {
                reject(err);
            });

            fileStream.on('data', (chunk) => {
                md5.update(chunk);
                sha1.update(chunk);
                sha256.update(chunk);
            });

            fileStream.on('end', () => {
                resolve({
                    md5: md5.digest('hex'),
                    sha1: sha1.digest('hex'),
                    sha256: sha256.digest('hex')
                });
            });
        });
    }

    /**
     * Generate hash from string content
     * @param {string} content - String content to hash
     * @param {string} algorithm - Hash algorithm
     * @returns {string} Hash of the content
     */
    static hashString(content, algorithm = 'sha256') {
        return crypto.createHash(algorithm).update(content).digest('hex');
    }

    /**
     * Verify file integrity by comparing hash
     * @param {string} filePath - Path to the file
     * @param {string} expectedHash - Expected hash value
     * @param {string} algorithm - Hash algorithm used
     * @returns {Promise<boolean>} True if hashes match
     */
    static async verifyHash(filePath, expectedHash, algorithm = 'sha256') {
        const actualHash = await this.generateHash(filePath, algorithm);
        return actualHash.toLowerCase() === expectedHash.toLowerCase();
    }
}

module.exports = HashGenerator;
