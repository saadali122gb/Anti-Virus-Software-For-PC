const { app, BrowserWindow, ipcMain, Tray, Menu, dialog } = require('electron');
const path = require('path');
const os = require('os');
const fs = require('fs-extra');
const FileScanner = require('./src/scanner/FileScanner');
const QuarantineManager = require('./src/quar/QuarantineManager');
const ThreatDatabase = require('./src/database/ThreatDatabase');
const FileWatcher = require('./src/realtime/FileWatcher');
const ThreatRemover = require('./src/removal/ThreatRemover');
const Logger = require('./src/utils/Logger');
const NetworkTool = require('./src/utils/NetworkTool');
const ConnectivityTool = require('./src/utils/ConnectivityTool');

let mainWindow;
let tray;
let fileWatcher;
const logger = new Logger();
const db = new ThreatDatabase();

// Check for administrator privileges
function isAdmin() {
  try {
    const { execSync } = require('child_process');
    execSync('net session', { stdio: 'ignore' });
    return true;
  } catch (e) {
    return false;
  }
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 1000,
    minHeight: 700,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false
    },
    backgroundColor: '#0a0e27',
    show: false
  });

  // Load a simple HTML page for now
  mainWindow.loadFile('src/ui/simple.html');

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();

    // Check admin privileges
    if (!isAdmin()) {
      dialog.showMessageBox(mainWindow, {
        type: 'warning',
        title: 'Administrator Privileges Required',
        message: 'This application requires administrator privileges for full functionality.',
        detail: 'Please restart the application as administrator for complete protection.',
        buttons: ['OK']
      });
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

function toggleRealTimeProtection(enabled) {
  if (enabled) {
    if (!fileWatcher) {
      fileWatcher = new FileWatcher();

      fileWatcher.on('threat-detected', (threat) => {
        if (mainWindow) mainWindow.webContents.send('realtime-threat', threat);
      });

      fileWatcher.on('threat-quarantined', (threat) => {
        if (mainWindow) mainWindow.webContents.send('realtime-threat-quarantined', threat);
      });

      fileWatcher.start();
      logger.info('Real-time protection enabled');
    }
  } else {
    if (fileWatcher) {
      fileWatcher.stop();
      fileWatcher.removeAllListeners();
      fileWatcher = null;
      logger.info('Real-time protection disabled');
    }
  }

  if (mainWindow) {
    mainWindow.webContents.send('realtime-status-changed', enabled);
  }
}

// IPC Handlers
ipcMain.handle('start-scan', async (event, options) => {
  try {
    let { type, paths = [] } = options;

    // If full scan, include all fixed drives
    if (type === 'full' && paths.length === 0) {
      const { execSync } = require('child_process');
      try {
        const drivesOutput = execSync('wmic logicaldisk get name').toString();
        const drives = drivesOutput.split('\r\n')
          .map(d => d.trim())
          .filter(d => /^[A-Z]:$/.test(d))
          .map(d => d + '\\');
        paths = drives;
      } catch (e) {
        paths = ['C:\\']; // Fallback
      }
    }

    logger.info(`Starting scan: ${type} on ${paths.join(', ')}`);
    const scanner = new FileScanner();

    scanner.on('progress', (data) => {
      mainWindow.webContents.send('scan-progress', data);
    });

    scanner.on('threat-found', (threat) => {
      mainWindow.webContents.send('threat-detected', threat);
      logger.warn(`Threat detected: ${threat.name} in ${threat.path}`);
    });

    const results = await scanner.scan(options);
    logger.info(`Scan completed: ${results.threatsFound} threats found`);

    return results;
  } catch (error) {
    logger.error(`Scan error: ${error.message}`);
    throw error;
  }
});

ipcMain.handle('scan-network', async () => {
  try {
    logger.info('Starting network audit');
    const devices = await NetworkTool.scanNetwork();
    logger.info(`Network audit complete: found ${devices.length} devices`);
    return devices;
  } catch (error) {
    logger.error(`Network scan error: ${error.message}`);
    throw error;
  }
});

ipcMain.handle('get-connectivity-details', async () => {
  try {
    logger.info('Starting connectivity audit');
    const local = ConnectivityTool.getLocalDetails();
    const publicIP = await ConnectivityTool.getPublicIP();
    const connection = await ConnectivityTool.getConnectionInfo();
    const speed = await ConnectivityTool.runSpeedTest();

    logger.info('Connectivity audit complete');
    return { local, publicIP, connection, speed };
  } catch (error) {
    logger.error(`Connectivity audit error: ${error.message}`);
    throw error;
  }
});

ipcMain.handle('optimize-system', async () => {
  try {
    logger.info('Starting system optimization');
    const tempDirs = [
      process.env.TEMP,
      path.join(os.homedir(), 'AppData/Local/Temp'),
      path.join(os.homedir(), 'AppData/Local/Microsoft/Windows/INetCache')
    ];

    let totalCleaned = 0;
    let errors = 0;

    for (const dir of tempDirs) {
      if (await fs.pathExists(dir)) {
        const files = await fs.readdir(dir);
        for (const file of files) {
          try {
            const filePath = path.join(dir, file);
            const stats = await fs.lstat(filePath);
            if (stats.isFile() || stats.isSymbolicLink()) {
              await fs.remove(filePath);
              totalCleaned++;
            }
          } catch (e) {
            errors++;
            // Skip files in use or inaccessible
          }
        }
      }
    }

    logger.info(`System optimization complete: cleaned ${totalCleaned} items, ${errors} skipped`);
    return { success: true, cleanedCount: totalCleaned, skippedCount: errors };
  } catch (error) {
    logger.error(`Optimization error: ${error.message}`);
    throw error;
  }
});

ipcMain.handle('select-folder', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openDirectory']
  });
  if (result.canceled) return null;
  return result.filePaths[0];
});

ipcMain.handle('quarantine-file', async (event, filePath) => {
  try {
    const quarantine = new QuarantineManager();
    const result = await quarantine.quarantineFile(filePath);
    logger.info(`File quarantined: ${filePath}`);
    return result;
  } catch (error) {
    logger.error(`Quarantine error: ${error.message}`);
    throw error;
  }
});

ipcMain.handle('restore-file', async (event, quarantineId) => {
  try {
    const quarantine = new QuarantineManager();
    const result = await quarantine.restoreFile(quarantineId);
    logger.info(`File restored: ${quarantineId}`);
    return result;
  } catch (error) {
    logger.error(`Restore error: ${error.message}`);
    throw error;
  }
});

ipcMain.handle('delete-quarantine', async (event, quarantineId) => {
  try {
    const quarantine = new QuarantineManager();
    await quarantine.permanentDelete(quarantineId);
    logger.info(`Quarantine deleted: ${quarantineId}`);
    return { success: true };
  } catch (error) {
    logger.error(`Delete error: ${error.message}`);
    throw error;
  }
});

ipcMain.handle('get-quarantine-list', async () => {
  try {
    const quarantine = new QuarantineManager();
    return await quarantine.getQuarantineList();
  } catch (error) {
    logger.error(`Get quarantine list error: ${error.message}`);
    throw error;
  }
});

ipcMain.handle('remove-threat', async (event, threatPath) => {
  try {
    const remover = new ThreatRemover();
    const result = await remover.removeThreat(threatPath);
    logger.info(`Threat removed: ${threatPath}`);
    return result;
  } catch (error) {
    logger.error(`Removal error: ${error.message}`);
    throw error;
  }
});

ipcMain.handle('get-scan-history', async () => {
  try {
    await db.initialize();
    return await db.getScanHistory();
  } catch (error) {
    logger.error(`Get scan history error: ${error.message}`);
    throw error;
  }
});

ipcMain.handle('get-statistics', async () => {
  try {
    await db.initialize();
    return await db.getStatistics();
  } catch (error) {
    logger.error(`Get statistics error: ${error.message}`);
    throw error;
  }
});

ipcMain.handle('toggle-realtime-protection', async (event, enabled) => {
  toggleRealTimeProtection(enabled);
  return { success: true, enabled };
});

ipcMain.handle('update-database', async () => {
  try {
    await db.initialize();
    await db.updateSignatures();
    logger.info('Database updated successfully');
    return { success: true };
  } catch (error) {
    logger.error(`Database update error: ${error.message}`);
    throw error;
  }
});

// App lifecycle
app.whenReady().then(() => {
  // Ensure required directories exist
  const dirs = [
    path.join(__dirname, 'quarantine'),
    path.join(__dirname, 'logs'),
    path.join(__dirname, 'database')
  ];

  dirs.forEach(dir => {
    fs.ensureDirSync(dir);
  });

  createWindow();

  // Initialize database
  const db = new ThreatDatabase();
  db.initialize().then(() => {
    logger.info('Threat database initialized');
  });

  // Start real-time protection by default
  toggleRealTimeProtection(true);

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('before-quit', () => {
  app.isQuitting = true;
  if (fileWatcher) {
    fileWatcher.stop();
  }
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  logger.error(`Uncaught exception: ${error.message}`);
  console.error(error);
});
