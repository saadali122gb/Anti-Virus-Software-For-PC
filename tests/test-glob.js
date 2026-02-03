const glob = require('glob');
const path = require('path');

const scanPath = 'd:\\Soft House\\Network Jammer\\src';
const pattern = '**/*';
const globPattern = path.join(scanPath, pattern);

console.log('Glob Pattern:', globPattern);

glob(globPattern, { nodir: true }, (err, matches) => {
    if (err) {
        console.error('Error:', err);
    } else {
        console.log('Matches found:', matches.length);
        if (matches.length > 0) {
            console.log('First match:', matches[0]);
        }
    }
});
