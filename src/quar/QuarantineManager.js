const fs = require('fs-extra');
const path = require('path');
const crypto = require('crypto');
const config = require('../config/config');
const Logger = require('../utils/Logger');

class QuarantineManager {
    constructor() {
        this.quarantinePath = config.paths.quarantine;
        this.logger = new Logger();
        this.encryptionKey = Buffer.from(config.quarantine.encryptionKey.padEnd(32, '0').substring(0, 32));

        // Ensure quarantine directory exists
        fs.ensureDirSync(this.quarantinePath);
    }

    /**
     * Quarantine a file
     * @param {string} filePath - Path to file to quarantine
     * @returns {Promise<Object>} Quarantine info
     */
    async quarantineFile(filePath) {
        try {
            // Check if file exists
            if (!await fs.pathExists(filePath)) {
                throw new Error('File not found');
            }

            const stats = await fs.stat(filePath);
            const fileName = path.basename(filePath);
            const quarantineId = this.generateQuarantineId();

            // Read file content
            const fileContent = await fs.readFile(filePath);

            // Encrypt file content
            const encryptedContent = this.encryptFile(fileContent);

            // Save encrypted file
            const quarantineFilePath = path.join(this.quarantinePath, `${quarantineId}.quar`);
            await fs.writeFile(quarantineFilePath, encryptedContent);

            // Save metadata
            const metadata = {
                id: quarantineId,
                originalPath: filePath,
                fileName: fileName,
                fileSize: stats.size,
                quarantinedAt: new Date().toISOString(),
                hash: crypto.createHash('sha256').update(fileContent).digest('hex')
            };

            const metadataPath = path.join(this.quarantinePath, `${quarantineId}.json`);
            await fs.writeJson(metadataPath, metadata, { spaces: 2 });

            // Delete original file
            await fs.remove(filePath);

            this.logger.logQuarantine('quarantined', filePath);

            return {
                success: true,
                quarantineId,
                message: `File quarantined successfully: ${fileName}`
            };
        } catch (error) {
            this.logger.error(`Quarantine error: ${error.message}`);
            throw error;
        }
    }

    /**
     * Restore a quarantined file
     * @param {string} quarantineId - Quarantine ID
     * @returns {Promise<Object>} Restore result
     */
    async restoreFile(quarantineId) {
        try {
            const metadataPath = path.join(this.quarantinePath, `${quarantineId}.json`);
            const quarantineFilePath = path.join(this.quarantinePath, `${quarantineId}.quar`);

            // Check if quarantine files exist
            if (!await fs.pathExists(metadataPath) || !await fs.pathExists(quarantineFilePath)) {
                throw new Error('Quarantined file not found');
            }

            // Read metadata
            const metadata = await fs.readJson(metadataPath);

            // Read encrypted file
            const encryptedContent = await fs.readFile(quarantineFilePath);

            // Decrypt file
            const decryptedContent = this.decryptFile(encryptedContent);

            // Restore to original location or safe location
            let restorePath = metadata.originalPath;

            // If original location is not accessible, restore to desktop
            if (!await fs.pathExists(path.dirname(restorePath))) {
                const os = require('os');
                restorePath = path.join(os.homedir(), 'Desktop', 'Restored_' + metadata.fileName);
            }

            // Write restored file
            await fs.writeFile(restorePath, decryptedContent);

            // Remove from quarantine
            await fs.remove(quarantineFilePath);
            await fs.remove(metadataPath);

            this.logger.logQuarantine('restored', restorePath);

            return {
                success: true,
                restoredPath: restorePath,
                message: `File restored to: ${restorePath}`
            };
        } catch (error) {
            this.logger.error(`Restore error: ${error.message}`);
            throw error;
        }
    }

    /**
     * Permanently delete a quarantined file
     * @param {string} quarantineId - Quarantine ID
     * @returns {Promise<Object>} Delete result
     */
    async permanentDelete(quarantineId) {
        try {
            const metadataPath = path.join(this.quarantinePath, `${quarantineId}.json`);
            const quarantineFilePath = path.join(this.quarantinePath, `${quarantineId}.quar`);

            // Remove quarantine files
            if (await fs.pathExists(quarantineFilePath)) {
                await fs.remove(quarantineFilePath);
            }

            if (await fs.pathExists(metadataPath)) {
                await fs.remove(metadataPath);
            }

            this.logger.logQuarantine('deleted', quarantineId);

            return {
                success: true,
                message: 'File permanently deleted from quarantine'
            };
        } catch (error) {
            this.logger.error(`Delete error: ${error.message}`);
            throw error;
        }
    }

    /**
     * Get list of quarantined files
     * @returns {Promise<Array>} List of quarantined files
     */
    async getQuarantineList() {
        try {
            const files = await fs.readdir(this.quarantinePath);
            const metadataFiles = files.filter(f => f.endsWith('.json'));

            const quarantineList = [];

            for (const metadataFile of metadataFiles) {
                const metadataPath = path.join(this.quarantinePath, metadataFile);
                const metadata = await fs.readJson(metadataPath);
                quarantineList.push(metadata);
            }

            // Sort by quarantine date (newest first)
            quarantineList.sort((a, b) =>
                new Date(b.quarantinedAt) - new Date(a.quarantinedAt)
            );

            return quarantineList;
        } catch (error) {
            this.logger.error(`Get quarantine list error: ${error.message}`);
            return [];
        }
    }

    /**
     * Encrypt file content
     * @param {Buffer} content - File content
     * @returns {Buffer} Encrypted content
     */
    encryptFile(content) {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', this.encryptionKey, iv);

        const encrypted = Buffer.concat([
            cipher.update(content),
            cipher.final()
        ]);

        // Prepend IV to encrypted content
        return Buffer.concat([iv, encrypted]);
    }

    /**
     * Decrypt file content
     * @param {Buffer} encryptedContent - Encrypted content
     * @returns {Buffer} Decrypted content
     */
    decryptFile(encryptedContent) {
        // Extract IV from beginning
        const iv = encryptedContent.slice(0, 16);
        const encrypted = encryptedContent.slice(16);

        const decipher = crypto.createDecipheriv('aes-256-cbc', this.encryptionKey, iv);

        return Buffer.concat([
            decipher.update(encrypted),
            decipher.final()
        ]);
    }

    /**
     * Generate unique quarantine ID
     * @returns {string} Quarantine ID
     */
    generateQuarantineId() {
        return `quar_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
    }

    /**
     * Clean old quarantine files
     * @param {number} daysOld - Delete files older than this many days
     */
    async cleanOldQuarantine(daysOld = 30) {
        try {
            const list = await this.getQuarantineList();
            const cutoffDate = new Date();
            cutoffDate.setDate(cutoffDate.getDate() - daysOld);

            for (const item of list) {
                const quarantineDate = new Date(item.quarantinedAt);
                if (quarantineDate < cutoffDate) {
                    await this.permanentDelete(item.id);
                    this.logger.info(`Auto-deleted old quarantine: ${item.id}`);
                }
            }
        } catch (error) {
            this.logger.error(`Clean old quarantine error: ${error.message}`);
        }
    }
}

module.exports = QuarantineManager;
