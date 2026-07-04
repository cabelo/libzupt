/*
 * libzupt - Random Bytes Example (Node.js)
 * Shows how to generate cryptographically secure random bytes
 *
 * SPDX-License-Identifier: MIT
 */

const zupt = require('./index');
const crypto = require('crypto');

function printHex(data, label = null, maxLen = 32) {
    if (label) {
        process.stdout.write(label + ': ');
    }
    process.stdout.write('[');
    const len = Math.min(maxLen, data.length);
    for (let i = 0; i < len; i++) {
        if (i > 0) process.stdout.write(' ');
        process.stdout.write(data[i].toString(16).padStart(2, '0'));
    }
    if (data.length > maxLen) {
        process.stdout.write(' ...');
    }
    process.stdout.write(']\n');
}

function main() {
    console.log('libzupt - Random Bytes Example (Node.js)');
    console.log('Library version:', zupt.getVersion());
    console.log('');

    try {
        // Step 1: Generate random bytes with libzupt
        console.log('Step 1: Generating 32 random bytes with libzupt...');
        const random1 = zupt.randomBytes(32);
        printHex(random1, 'libzupt random');

        // Step 2: Generate multiple random byte sequences
        console.log('');
        console.log('Step 2: Generating 5 different random sequences...');
        for (let i = 0; i < 5; i++) {
            const rb = zupt.randomBytes(16);
            console.log('  Sequence', i + 1, ':', rb.toString('hex'));
        }

        // Step 3: Generate various sizes
        console.log('');
        console.log('Step 3: Generating various sizes...');
        const sizes = [8, 16, 32, 64, 128, 256, 1024];
        for (const size of sizes) {
            const rb = zupt.randomBytes(size);
            console.log('  Size', size, ':', rb.length, 'bytes generated');
        }

        // Step 4: Verify randomness (check for uniqueness)
        console.log('');
        console.log('Step 4: Verifying uniqueness of random values...');
        const samples = new Set();
        for (let i = 0; i < 100; i++) {
            const rb = zupt.randomBytes(32);
            samples.add(rb.toString('hex'));
        }
        console.log('  Generated 100 samples, unique count:', samples.size);
        if (samples.size === 100) {
            console.log('  SUCCESS: All samples are unique!');
        } else {
            console.log('  WARNING: Some duplicate values found');
        }

        // Step 5: Compare with Node.js crypto module
        console.log('');
        console.log('Step 5: Comparing with Node.js crypto.randomBytes...');
        const zuptRandom = zupt.randomBytes(32);
        const cryptoRandom = crypto.randomBytes(32);
        printHex(zuptRandom, 'libzupt');
        printHex(cryptoRandom, 'crypto');
        console.log('  Both sources generate 32 bytes of random data');

        // Step 6: Use random bytes for key generation
        console.log('');
        console.log('Step 6: Using random bytes in key generation...');
        const keygen = new zupt.KeyGenerator();
        const keypair = keygen.generateKeyPair();
        console.log('  Key pair generated using internal randomness');

        // Step 7: Generate salt for password hashing
        console.log('');
        console.log('Step 7: Generating salt for password hashing...');
        const salt = zupt.randomBytes(32); // 256-bit salt
        console.log('  Salt:', salt.toString('hex'));

        // Step 8: Generate initialization vectors (IVs)
        console.log('');
        console.log('Step 8: Generating IVs for encryption...');
        const ivs = [];
        for (let i = 0; i < 3; i++) {
            const iv = zupt.randomBytes(16); // AES block size
            ivs.push(iv);
            console.log('  IV', i + 1, ':', iv.toString('hex'));
        }

        // Step 9: Generate nonce values
        console.log('');
        console.log('Step 9: Generating nonces...');
        const nonces = [];
        for (let i = 0; i < 3; i++) {
            const nonce = zupt.randomBytes(12); // Typical nonce size
            nonces.push(nonce);
            console.log('  Nonce', i + 1, ':', nonce.toString('hex'));
        }

        // Step 10: Generate cryptographically strong password
        console.log('');
        console.log('Step 10: Generating a cryptographically strong password...');
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()';
        const passwordLen = 24;
        const passwordBuf = zupt.randomBytes(passwordLen);
        let password = '';
        for (let i = 0; i < passwordLen; i++) {
            password += chars[passwordBuf[i] % chars.length];
        }
        console.log('  Generated password:', password);
        console.log('  (In production, use a proper password generator with character constraints)');

        console.log('');
        console.log('All random byte examples completed successfully!');

    } catch (err) {
        console.error('Error:', err.message);
        if (err.stack) {
            console.error(err.stack);
        }
        process.exit(1);
    }
}

main();
