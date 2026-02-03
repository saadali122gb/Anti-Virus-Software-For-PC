const { exec } = require('child_process');
const os = require('os');

class NetworkTool {
    /**
     * Scan the local network for active devices
     * @returns {Promise<Array>} List of devices
     */
    static async scanNetwork() {
        return new Promise((resolve) => {
            // Using arp -a as it's the fastest way to get local neighbors on Windows
            exec('arp -a', (error, stdout) => {
                if (error) {
                    console.error('Network scan error:', error);
                    resolve([]);
                    return;
                }

                const devices = this.parseArpOutput(stdout);
                resolve(devices);
            });
        });
    }

    /**
     * Parse arp -a output into structured data
     */
    static parseArpOutput(output) {
        const lines = output.split('\n');
        const devices = [];
        const seenIps = new Set();

        // Get local IP for tagging
        const localInterface = this.getLocalInterface();

        lines.forEach(line => {
            // Match IP and MAC addresses
            const match = line.trim().match(/(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f-]{17})\s+(\w+)/i);
            if (match) {
                const ip = match[1];
                const mac = match[2];
                const type = match[3];

                // Filter out loopback, broadcast and duplicates
                if (!ip.startsWith('224.') && !ip.startsWith('239.') && !ip.endsWith('.255') && !seenIps.has(ip)) {
                    devices.push({
                        ip,
                        mac,
                        type,
                        isLocal: ip === localInterface,
                        hostname: ip === localInterface ? os.hostname() : 'Unknown Device'
                    });
                    seenIps.add(ip);
                }
            }
        });

        return devices;
    }

    static getLocalInterface() {
        const interfaces = os.networkInterfaces();
        for (const name of Object.keys(interfaces)) {
            for (const iface of interfaces[name]) {
                if (!iface.internal && iface.family === 'IPv4') {
                    return iface.address;
                }
            }
        }
        return '127.0.0.1';
    }
}

module.exports = NetworkTool;
