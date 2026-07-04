/*
 * libzupt - Basic Example (Node.js)
 * Shows how to generate keys, encrypt and decrypt data in memory
 *
 * SPDX-License-Identifier: MIT
 */

const zupt = require('./index');
const fs = require('fs');
const path = require('path');

function printHex(data, label = null) {
    if (label) {
        process.stdout.write(label + ': ');
    }
    process.stdout.write('[');
    const len = Math.min(16, data.length);
    for (let i = 0; i < len; i++) {
        if (i > 0) process.stdout.write(' ');
        process.stdout.write(data[i].toString(16).padStart(2, '0'));
    }
    if (data.length > 16) {
        process.stdout.write(' ...');
    }
    process.stdout.write(']\n');
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function main() {
    console.log('libzupt - Hybrid Post-Quantum Encryption Example (Node.js)');
    console.log('Library version:', zupt.getVersion());
    console.log('');

    try {
        // Step 1: Generate key pair
        console.log('Step 1: Generating hybrid key pair (ML-KEM-768 + X25519)...');
        const keygen = new zupt.KeyGenerator();
        const keypair = keygen.generateKeyPair();

        console.log('  Public key size:', keypair.publicKey.length, 'bytes');
        console.log('  Secret key size:', keypair.secretKey.length, 'bytes');
        printHex(keypair.publicKey, 'Public key (first 16 bytes)');
        console.log('');

        // Step 2: Encrypt data in memory
        console.log('Step 2: Encrypting data in memory...');
        const plaintext = 'Hello, Post-Quantum World! This is a secret message.';
        console.log('  Plaintext:', plaintext);

        const encryptor = new zupt.Encryptor(keypair.publicKey);
        const { ciphertext, encHeader } = encryptor.encryptMemory(
            Buffer.from(plaintext, 'utf8')
        );

        console.log('  Ciphertext size:', ciphertext.length, 'bytes');
        console.log('  Encryption header size:', encHeader.length, 'bytes');
        printHex(ciphertext, 'Ciphertext (first 16 bytes)');
        console.log('');

        // Step 3: Decrypt data in memory
        console.log('Step 3: Decrypting data in memory...');
        const decryptor = new zupt.Decryptor(keypair.secretKey);
        const decrypted = decryptor.decryptMemory(ciphertext, encHeader);

        const decryptedStr = decrypted.toString('utf8');
        console.log('  Decrypted:', decryptedStr);
        console.log('');

        // Step 4: Verify decryption
        console.log('Step 4: Verifying decryption...');
        if (decryptedStr === plaintext) {
            console.log('  SUCCESS: Decrypted text matches original!');
        } else {
            console.log('  ERROR: Decrypted text does not match!');
            process.exit(1);
        }
        console.log('');

        // Step 5: Save keys to files
        console.log('Step 5: Saving keys to files...');
        const keyDir = '/tmp/libzupt_nodejs_test';
        fs.mkdirSync(keyDir, { recursive: true });

        const keyfilePath = path.join(keyDir, 'test_keypair.key');
        const pubKeyPath = path.join(keyDir, 'test_pubkey.key');

        keygen.saveKeyPair(keypair, keyfilePath);
        keygen.exportPublicKey(keyfilePath, pubKeyPath);

        console.log('  Saved private key to:', keyfilePath);
        console.log('  Saved public key to:', pubKeyPath);
        console.log('');

        // Step 6: Demonstrate file encryption
        console.log('Step 6: Encrypting a file...');
        const testFile = path.join(keyDir, 'testfile.txt');
        const encFile = path.join(keyDir, 'testfile.zupt');

        // Create test file
        fs.writeFileSync(testFile, 'This is a test file for libzupt file encryption.\n');
        fs.appendFileSync(testFile, 'Line 2: More secret data.\n');
        fs.appendFileSync(testFile, 'Line 3: End of file.\n');

        // Encrypt file
        const { ciphertext: fileCiphertext, encHeader: fileEncHeader } =
            encryptor.encryptFile(testFile);

        console.log('  Encrypted file size:', fileCiphertext.length, 'bytes');

        // Save encrypted data
        fs.writeFileSync(encFile, fileCiphertext);

        // Decrypt file
        const fileDecrypted = decryptor.decryptFile(encFile, fileEncHeader);
        console.log('  Decrypted file content:');
        console.log(fileDecrypted.toString('utf8'));

        // Step 7: Demonstrate SecureBuffer
        console.log('');
        console.log('Step 7: Using SecureBuffer for sensitive data...');
        const secureBuf = new zupt.SecureBuffer(256);
        const sensitiveData = Buffer.from('secret-password-123', 'utf8');
        secureBuf.copy(sensitiveData);
        console.log('  SecureBuffer created with', secureBuf.size, 'bytes');
        secureBuf.zeroize();
        console.log('  SecureBuffer zeroized');

        // Step 8: Demonstrate random bytes generation
        console.log('');
        console.log('Step 8: Generating cryptographically secure random bytes...');
        const randomBytes = zupt.randomBytes(32);
        printHex(randomBytes, 'Random bytes');

        console.log('');
        console.log('All examples completed successfully!');

        // Cleanup
        fs.unlinkSync(testFile);
        fs.unlinkSync(encFile);
        fs.unlinkSync(keyfilePath);
        fs.unlinkSync(pubKeyPath);
        fs.rmdirSync(keyDir);

    } catch (err) {
        console.error('Error:', err.message);
        if (err.stack) {
            console.error(err.stack);
        }
        process.exit(1);
    }
}

main();
