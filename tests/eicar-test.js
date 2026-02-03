const fs = require('fs-extra');
const path = require('path');

/**
 * EICAR Test File
 * This is a standard antivirus test file that should be detected by all antivirus software
 */

async function testEICAR() {
    console.log('=== EICAR Test File Detection ===\n');

    // EICAR test string (standard antivirus test file)
    const eicarString = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';

    const testDir = path.join(__dirname, 'temp');
    const testFile = path.join(testDir, 'eicar.com');

    try {
        // Create test directory
        await fs.ensureDir(testDir);

        // Create EICAR test file
        await fs.writeFile(testFile, eicarString);
        console.log(`✓ Created EICAR test file: ${testFile}`);

        // Import scanner
        const FileScanner = require('../src/scanner/FileScanner');
        const scanner = new FileScanner();

        console.log('\\n🔍 Scanning EICAR test file...');

        // Scan the file
        const threat = await scanner.scanFile(testFile);

        if (threat) {
            console.log('\\n✅ TEST PASSED: EICAR file detected!');
            console.log('Threat Details:');
            console.log(`  Name: ${threat.name}`);
            console.log(`  Type: ${threat.type}`);
            console.log(`  Severity: ${threat.severity}`);
            console.log(`  Method: ${threat.detectionMethod}`);
        } else {
            console.log('\\n❌ TEST FAILED: EICAR file not detected');
        }

        // Cleanup
        await fs.remove(testDir);
        console.log('\\n✓ Cleaned up test files');

    } catch (error) {
        console.error('\\n❌ Test error:', error.message);
        // Cleanup on error
        try {
            await fs.remove(testDir);
        } catch (e) {
            // Ignore cleanup errors
        }
    }
}

// Run test
testEICAR().then(() => {
    console.log('\\n=== Test Complete ===');
    process.exit(0);
}).catch(error => {
    console.error('Test failed:', error);
    process.exit(1);
});
