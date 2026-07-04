/*
 * libzupt - Key Generation Example (Node.js)
 * Shows how to generate, save, load, and manage key pairs
 *
 * SPDX-License-Identifier: MIT
 */

const zupt = require('./index');
const fs = require('fs');
const path = require('path');

function main() {
    console.log('libzupt - Key Generation Example (Node.js)');
    console.log('Library version:', zupt.getVersion());
    console.log('');

    const testDir = '/tmp/libzupt_keygen_test';
    fs.mkdirSync(testDir, { recursive: true });

    try {
        const privKeyFile = path.join(testDir, 'keys.pem');
        const pubKeyFile = path.join(testDir, 'keys.pub.pem');

        // Step 1: Generate new key pair
        console.log('Step 1: Generating new key pair...');
        const keygen = new zupt.KeyGenerator();
        const keypair = keygen.generateKeyPair();

        console.log('  Public key size:', keypair.publicKey.length, 'bytes');
        console.log('  Secret key size:', keypair.secretKey.length, 'bytes');
        console.log('  Public key (hex, first 32 bytes):');
        console.log('  ', keypair.publicKey.slice(0, 32).toString('hex'));

        // Step 2: Save key pair to file
        console.log('');
        console.log('Step 2: Saving key pair to file...');
        keygen.saveKeyPair(keypair, privKeyFile);
        console.log('  Saved to:', privKeyFile);

        // Step 3: Export public key
        console.log('');
        console.log('Step 3: Exporting public key...');
        keygen.exportPublicKey(privKeyFile, pubKeyFile);
        console.log('  Saved to:', pubKeyFile);

        // Step 4: Load public key from file
        console.log('');
        console.log('Step 4: Loading public key from file...');
        const publicKey = keygen.loadPublicKey(pubKeyFile);
        console.log('  Loaded public key size:', publicKey.length, 'bytes');

        // Step 5: Load key pair from file
        console.log('');
        console.log('Step 5: Loading key pair from file...');
        const loadedKeyPair = keygen.loadKeyPair(privKeyFile);
        console.log('  Loaded public key size:', loadedKeyPair.publicKey.length, 'bytes');
        console.log('  Loaded secret key size:', loadedKeyPair.secretKey.length, 'bytes');

        // Step 6: Verify keys match
        console.log('');
        console.log('Step 6: Verifying keys...');
        let keysMatch = true;
        if (loadedKeyPair.publicKey.length !== keypair.publicKey.length) {
            keysMatch = false;
        } else {
            for (let i = 0; i < keypair.publicKey.length; i++) {
                if (loadedKeyPair.publicKey[i] !== keypair.publicKey[i]) {
                    keysMatch = false;
                    break;
                }
            }
        }

        if (keysMatch) {
            console.log('  SUCCESS: Keys match!');
        } else {
            console.log('  ERROR: Keys do not match!');
        }

        // Step 7: Demonstrate key size constants
        console.log('');
        console.log('Step 7: Key sizes:');
        console.log('  ML-KEM-768 Public Key: 1184 bytes');
        console.log('  ML-KEM-768 Secret Key: 2400 bytes');
        console.log('  X25519 Key: 32 bytes');
        console.log('  Hybrid Public Key: 1224 bytes (8 header + 1184 ML + 32 X25519)');
        console.log('  Hybrid Secret Key: ~3664 bytes (includes public key + private keys + checksum)');

        // Step 8: Generate multiple key pairs (demonstrate randomness)
        console.log('');
        console.log('Step 8: Generating 3 key pairs to verify randomness...');
        for (let i = 0; i < 3; i++) {
            const kp = keygen.generateKeyPair();
            const firstBytes = kp.publicKey.slice(0, 8).toString('hex');
            console.log('  Key pair', i + 1, 'public key prefix:', firstBytes);
        }

        // Step 9: Demonstrate use with encryption
        console.log('');
        console.log('Step 9: Using generated keys for encryption...');
        const message = 'This message will be encrypted with the generated key pair.';
        const textBuffer = Buffer.from(message, 'utf8');

        // Encrypt using the public key we exported
        const encryptor = new zupt.Encryptor(publicKey);
        const { ciphertext, encHeader } = encryptor.encryptMemory(textBuffer);

        console.log('  Encrypted message size:', ciphertext.length, 'bytes');

        // Decrypt using the loaded private key
        const decryptor = new zupt.Decryptor(loadedKeyPair.secretKey);
        const decrypted = decryptor.decryptMemory(ciphertext, encHeader);
        const decryptedMessage = decrypted.toString('utf8');

        if (decryptedMessage === message) {
            console.log('  SUCCESS: Encryption/decryption with loaded keys works!');
        } else {
            console.log('  ERROR: Decrypted message does not match!');
        }

        console.log('');
        console.log('All key generation examples completed successfully!');

    } catch (err) {
        console.error('Error:', err.message);
        if (err.stack) {
            console.error(err.stack);
        }
        process.exit(1);
    } finally {
        // Cleanup
        try {
            fs.unlinkSync(path.join(testDir, 'keys.pem'));
            fs.unlinkSync(path.join(testDir, 'keys.pub.pem'));
            fs.rmdirSync(testDir);
        } catch (e) {
            // Ignore cleanup errors
        }
    }
}

main();
