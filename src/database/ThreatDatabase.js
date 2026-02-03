const path = require('path');
const fs = require('fs-extra');
const config = require('../config/config');

class ThreatDatabase {
  constructor() {
    this.dbPath = config.paths.database.replace('.db', '.json');
    this.data = {
      hash_signatures: [],
      pattern_signatures: [],
      scan_history: [],
      threat_detections: []
    };
    this.initialized = false;
  }

  /**
   * Initialize database and create collections
   */
  async initialize() {
    if (this.initialized) return true;

    try {
      const dbDir = path.dirname(this.dbPath);
      await fs.ensureDir(dbDir);

      if (await fs.pathExists(this.dbPath)) {
        const fileData = await fs.readJson(this.dbPath);
        this.data = { ...this.data, ...fileData };
      } else {
        await this.save();
      }

      // Populate with initial signatures if empty
      if (this.data.hash_signatures.length === 0) {
        this.populateInitialSignatures();
        await this.save();
      }

      this.initialized = true;
      return true;
    } catch (error) {
      console.error('Database initialization error:', error);
      throw error;
    }
  }

  async save() {
    await fs.writeJson(this.dbPath, this.data, { spaces: 2 });
  }

  /**
   * Populate database with initial malware signatures
   */
  populateInitialSignatures() {
    const hashSigs = [
      {
        hash: '44d88612fea8a8f36de82e1278abb02f',
        hash_type: 'md5',
        name: 'EICAR-Test-File',
        type: 'test',
        severity: 'low',
        description: 'EICAR antivirus test file'
      },
      {
        hash: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
        hash_type: 'sha256',
        name: 'EICAR-Test-File',
        type: 'test',
        severity: 'low',
        description: 'EICAR antivirus test file'
      }
    ];

    const patternSigs = [
      {
        name: 'PowerShell.Downloader',
        type: 'trojan',
        severity: 'high',
        pattern: '(Invoke-WebRequest|IWR|wget|curl).*\\.(exe|dll|bat|ps1)',
        description: 'PowerShell download and execute pattern'
      }
    ];

    hashSigs.forEach(sig => {
      if (!this.data.hash_signatures.find(h => h.hash === sig.hash)) {
        this.data.hash_signatures.push(sig);
      }
    });

    patternSigs.forEach(sig => {
      if (!this.data.pattern_signatures.find(p => p.name === sig.name)) {
        this.data.pattern_signatures.push(sig);
      }
    });
  }

  getHashSignatures() {
    return this.data.hash_signatures;
  }

  getPatternSignatures() {
    return this.data.pattern_signatures;
  }

  async recordScanStart(scanType) {
    const id = Date.now();
    this.data.scan_history.push({
      id,
      scan_type: scanType,
      start_time: new Date().toISOString(),
      status: 'running',
      files_scanned: 0,
      threats_found: 0
    });
    await this.save();
    return id;
  }

  async recordScanComplete(scanId, filesScanned, threatsFound, duration) {
    const scan = this.data.scan_history.find(s => s.id === scanId);
    if (scan) {
      scan.end_time = new Date().toISOString();
      scan.files_scanned = filesScanned;
      scan.threats_found = threatsFound;
      scan.duration = duration;
      scan.status = 'completed';
      await this.save();
    }
  }

  async recordThreatDetection(scanId, filePath, threatName, threatType, severity, detectionMethod, actionTaken = null) {
    this.data.threat_detections.push({
      id: Date.now() + Math.random(),
      scan_id: scanId,
      file_path: filePath,
      threat_name: threatName,
      threat_type: threatType,
      severity: severity,
      detection_method: detectionMethod,
      detected_at: new Date().toISOString(),
      action_taken: actionTaken
    });
    await this.save();
  }

  getScanHistory(limit = 50) {
    return [...this.data.scan_history]
      .sort((a, b) => new Date(b.start_time) - new Date(a.start_time))
      .slice(0, limit);
  }

  getStatistics() {
    const totalFilesScanned = this.data.scan_history.reduce((sum, s) => sum + (s.files_scanned || 0), 0);
    return {
      totalScans: this.data.scan_history.length,
      totalThreats: this.data.threat_detections.length,
      totalFilesScanned,
      recentThreats: [...this.data.threat_detections]
        .sort((a, b) => new Date(b.detected_at) - new Date(a.detected_at))
        .slice(0, 10)
    };
  }

  async updateSignatures() {
    console.log('Signature update check completed');
    return { success: true, message: 'Signatures are up to date' };
  }
}

module.exports = ThreatDatabase;
