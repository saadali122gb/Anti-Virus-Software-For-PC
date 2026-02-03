const fs = require('fs-extra');
const path = require('path');
const { exec } = require('child_process');
const { promisify } = require('util');
const Logger = require('../utils/Logger');

const execAsync = promisify(exec);

class ThreatRemover {
    constructor() {
        this.logger = new Logger();
    }

    /**
     * Remove a threat from the system
     * @param {string} threatPath - Path to threat file
     * @param {Object} options - Removal options
     * @returns {Promise<Object>} Removal result
     */
    async removeThreat(threatPath, options = {}) {
        const {
            cleanRegistry = true,
            cleanStartup = true,
            cleanTasks = true
        } = options;

        try {
            const results = {
                fileRemoved: false,
                registryCleaned: false,
                startupCleaned: false,
                tasksCleaned: false,
                errors: []
            };

            // Remove the file
            if (await fs.pathExists(threatPath)) {
                await this.secureDelete(threatPath);
                results.fileRemoved = true;
                this.logger.info(`File removed: ${threatPath}`);
            }

            // Clean registry entries (Windows only)
            if (cleanRegistry && process.platform === 'win32') {
                try {
                    await this.cleanRegistryEntries(threatPath);
                    results.registryCleaned = true;
                } catch (error) {
                    results.errors.push(`Registry cleaning failed: ${error.message}`);
                }
            }

            // Clean startup entries
            if (cleanStartup) {
                try {
                    await this.cleanStartupEntries(threatPath);
                    results.startupCleaned = true;
                } catch (error) {
                    results.errors.push(`Startup cleaning failed: ${error.message}`);
                }
            }

            // Clean scheduled tasks
            if (cleanTasks && process.platform === 'win32') {
                try {
                    await this.cleanScheduledTasks(threatPath);
                    results.tasksCleaned = true;
                } catch (error) {
                    results.errors.push(`Task cleaning failed: ${error.message}`);
                }
            }

            this.logger.logRemoval(threatPath, results.fileRemoved);

            return {
                success: results.fileRemoved,
                results,
                message: 'Threat removal completed'
            };
        } catch (error) {
            this.logger.error(`Threat removal error: ${error.message}`);
            throw error;
        }
    }

    /**
     * Securely delete a file
     * @param {string} filePath - Path to file
     */
    async secureDelete(filePath) {
        try {
            // Get file stats
            const stats = await fs.stat(filePath);

            // Overwrite file with random data before deletion
            const fd = await fs.open(filePath, 'r+');
            const buffer = Buffer.alloc(Math.min(stats.size, 1024 * 1024)); // 1MB chunks

            // Fill with random data
            for (let i = 0; i < buffer.length; i++) {
                buffer[i] = Math.floor(Math.random() * 256);
            }

            // Overwrite file
            let position = 0;
            while (position < stats.size) {
                const writeSize = Math.min(buffer.length, stats.size - position);
                await fs.write(fd, buffer, 0, writeSize, position);
                position += writeSize;
            }

            await fs.close(fd);

            // Delete the file
            await fs.remove(filePath);

            return true;
        } catch (error) {
            // If secure delete fails, try normal delete
            try {
                await fs.remove(filePath);
                return true;
            } catch (e) {
                throw error;
            }
        }
    }

    /**
     * Clean registry entries related to threat
     * @param {string} threatPath - Path to threat file
     */
    async cleanRegistryEntries(threatPath) {
        if (process.platform !== 'win32') return;

        const fileName = path.basename(threatPath);
        const registryKeys = [
            'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
            'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
            'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
            'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
        ];

        for (const key of registryKeys) {
            try {
                // Query registry key
                const { stdout } = await execAsync(`reg query "${key}"`);

                // Check if threat path is in registry
                if (stdout.includes(threatPath) || stdout.includes(fileName)) {
                    // Find the value name
                    const lines = stdout.split('\n');
                    for (const line of lines) {
                        if (line.includes(threatPath) || line.includes(fileName)) {
                            const match = line.match(/^\s+(\S+)\s+REG_/);
                            if (match) {
                                const valueName = match[1];
                                // Delete the registry value
                                await execAsync(`reg delete "${key}" /v "${valueName}" /f`);
                                this.logger.info(`Removed registry entry: ${key}\\${valueName}`);
                            }
                        }
                    }
                }
            } catch (error) {
                // Key might not exist or access denied, continue
            }
        }
    }

    /**
     * Clean startup entries
     * @param {string} threatPath - Path to threat file
     */
    async cleanStartupEntries(threatPath) {
        const fileName = path.basename(threatPath);
        const os = require('os');

        // Common startup folders
        const startupFolders = [
            path.join(os.homedir(), 'AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup'),
            'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup'
        ];

        for (const folder of startupFolders) {
            try {
                if (await fs.pathExists(folder)) {
                    const files = await fs.readdir(folder);

                    for (const file of files) {
                        const filePath = path.join(folder, file);

                        // Check if it's a shortcut to the threat
                        if (file.endsWith('.lnk')) {
                            // Read shortcut target (simplified check)
                            const content = await fs.readFile(filePath, 'utf8');
                            if (content.includes(threatPath) || content.includes(fileName)) {
                                await fs.remove(filePath);
                                this.logger.info(`Removed startup entry: ${filePath}`);
                            }
                        }
                    }
                }
            } catch (error) {
                // Continue if folder doesn't exist or access denied
            }
        }
    }

    /**
     * Clean scheduled tasks related to threat
     * @param {string} threatPath - Path to threat file
     */
    async cleanScheduledTasks(threatPath) {
        if (process.platform !== 'win32') return;

        try {
            // List all scheduled tasks
            const { stdout } = await execAsync('schtasks /query /fo LIST /v');

            const fileName = path.basename(threatPath);
            const lines = stdout.split('\n');

            let currentTask = null;
            let shouldDelete = false;

            for (const line of lines) {
                if (line.startsWith('TaskName:')) {
                    // Save previous task if it should be deleted
                    if (currentTask && shouldDelete) {
                        try {
                            await execAsync(`schtasks /delete /tn "${currentTask}" /f`);
                            this.logger.info(`Removed scheduled task: ${currentTask}`);
                        } catch (e) {
                            // Task might not exist or access denied
                        }
                    }

                    // Reset for new task
                    currentTask = line.split('TaskName:')[1].trim();
                    shouldDelete = false;
                }

                // Check if task references the threat
                if (line.includes(threatPath) || line.includes(fileName)) {
                    shouldDelete = true;
                }
            }

            // Check last task
            if (currentTask && shouldDelete) {
                try {
                    await execAsync(`schtasks /delete /tn "${currentTask}" /f`);
                    this.logger.info(`Removed scheduled task: ${currentTask}`);
                } catch (e) {
                    // Task might not exist or access denied
                }
            }
        } catch (error) {
            // schtasks might fail, continue
        }
    }

    /**
     * Kill processes associated with threat
     * @param {string} processName - Process name
     */
    async killProcess(processName) {
        try {
            if (process.platform === 'win32') {
                await execAsync(`taskkill /F /IM "${processName}"`);
            } else {
                await execAsync(`pkill -9 "${processName}"`);
            }
            this.logger.info(`Killed process: ${processName}`);
            return true;
        } catch (error) {
            // Process might not be running
            return false;
        }
    }
}

module.exports = ThreatRemover;
