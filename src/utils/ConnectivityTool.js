const os = require('os');
const { exec } = require('child_process');
const { promisify } = require('util');
const https = require('https');

const execAsync = promisify(exec);

class ConnectivityTool {
    /**
     * Get local network interface details
     */
    static getLocalDetails() {
        const interfaces = os.networkInterfaces();
        const details = [];

        for (const [name, info] of Object.entries(interfaces)) {
            for (const addr of info) {
                if (addr.family === 'IPv4' && !addr.internal) {
                    details.push({
                        interface: name,
                        ip: addr.address,
                        mac: addr.mac,
                        netmask: addr.netmask
                    });
                }
            }
        }
        return details;
    }

    /**
     * Get public IP address
     */
    static async getPublicIP() {
        return new Promise((resolve) => {
            https.get('https://api.ipify.org?format=json', (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    try {
                        resolve(JSON.parse(data).ip);
                    } catch (e) {
                        resolve('Unknown');
                    }
                });
            }).on('error', () => resolve('Unknown'));
        });
    }

    /**
     * Run a lightweight speed test (download)
     * Measures speed by downloading a 1MB file
     */
    static async runSpeedTest() {
        const testUrl = 'https://speed.cloudflare.com/__down?bytes=15728640'; // 15MB test payload
        let startTime = null;

        return new Promise((resolve) => {
            https.get(testUrl, (res) => {
                let bytesReceived = 0;
                res.on('data', chunk => {
                    if (startTime === null) startTime = Date.now(); // Start timer on first data arrival
                    bytesReceived += chunk.length;
                });
                res.on('end', () => {
                    const endTime = Date.now();
                    const durationSeconds = (endTime - (startTime || Date.now())) / 1000;

                    if (durationSeconds <= 0) {
                        return resolve({ speedMbps: 0, duration: 0, sizeBytes: bytesReceived });
                    }

                    const bitsLoaded = bytesReceived * 8;
                    const speedBps = bitsLoaded / durationSeconds;
                    const speedMbps = (speedBps / (1024 * 1024)).toFixed(2);

                    resolve({
                        speedMbps: parseFloat(speedMbps),
                        duration: durationSeconds.toFixed(2),
                        sizeBytes: bytesReceived
                    });
                });
            }).on('error', (err) => {
                resolve({ error: err.message, speedMbps: 0 });
            });
        });
    }

    /**
     * Get active connection info using Windows netsh
     */
    static async getConnectionInfo() {
        if (process.platform !== 'win32') return { type: 'Unknown' };

        try {
            const { stdout } = await execAsync('netsh wlan show interfaces');
            if (stdout.includes('SSID')) {
                const ssid = stdout.match(/SSID\s*:\s*(.*)/)?.[1]?.trim() || 'Unknown';
                const signal = stdout.match(/Signal\s*:\s*(.*)/)?.[1]?.trim() || 'Unknown';
                return { type: 'WiFi', ssid, signal };
            }
            return { type: 'Ethernet/Other' };
        } catch (e) {
            return { type: 'Wired/Unknown' };
        }
    }
}

module.exports = ConnectivityTool;
