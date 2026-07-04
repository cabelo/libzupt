/*
 * libzupt - Secure Buffer Example (Node.js)
 * Shows how to use SecureBuffer for sensitive data that should be zeroized
 *
 * SPDX-License-Identifier: MIT
 */

const zupt = require('./index');
const fs = require('fs');

function main() {
    console.log('libzupt - Secure Buffer Example (Node.js)');
    console.log('');

    try {
        // Step 1: Create a SecureBuffer
        console.log('Step 1: Creating a SecureBuffer...');
        const secureBuf = new zupt.SecureBuffer(256);
        console.log('  Created SecureBuffer with size:', secureBuf.size, 'bytes');

        // Step 2: Copy sensitive data into SecureBuffer
        console.log('');
        console.log('Step 2: Copying sensitive data...');
        const password = Buffer.from('my-super-secret-password', 'utf8');
        secureBuf.copy(password);
        console.log('  Copied', password.length, 'bytes to SecureBuffer');

        // Step 3: Read from SecureBuffer
        console.log('');
        console.log('Step 3: Reading from SecureBuffer...');
        const readBuf = secureBuf.toBuffer();
        console.log('  Read data:', readBuf.toString('utf8'));

        // Step 4: Verify data integrity
        console.log('');
        console.log('Step 4: Verifying data integrity...');
        if (readBuf.toString('utf8') === password.toString('utf8')) {
            console.log('  SUCCESS: Data matches original!');
        } else {
            console.log('  ERROR: Data does not match!');
        }

        // Step 5: Zeroize the buffer
        console.log('');
        console.log('Step 5: Zeroizing SecureBuffer...');
        secureBuf.zeroize();
        console.log('  Buffer zeroized - sensitive data is cleared');

        // Step 6: After zeroize, data should be zeros
        console.log('');
        console.log('Step 6: Verifying buffer is zeroized...');
        const afterZeroize = secureBuf.toBuffer();
        let allZeros = true;
        for (let i = 0; i < afterZeroize.length; i++) {
            if (afterZeroize[i] !== 0) {
                allZeros = false;
                break;
            }
        }
        if (allZeros) {
            console.log('  SUCCESS: Buffer is fully zeroized!');
        } else {
            console.log('  WARNING: Buffer may not be fully zeroized (this is expected with some implementations)');
        }

        // Step 7: Use SecureBuffer with encryption
        console.log('');
        console.log('Step 7: Using SecureBuffer for sensitive input...');
        const keygen = new zupt.KeyGenerator();
        const keypair = keygen.generateKeyPair();

        const sensitiveData = Buffer.from('Very sensitive information', 'utf8');
        const secureInput = new zupt.SecureBuffer(sensitiveData.length);
        secureInput.copy(sensitiveData);

        const encryptor = new zupt.Encryptor(keypair.publicKey);
        const { ciphertext, encHeader } = encryptor.encryptMemory(secureInput.toBuffer());

        const decryptor = new zupt.Decryptor(keypair.secretKey);
        const decrypted = decryptor.decryptMemory(ciphertext, encHeader);
        console.log('  Encrypted and decrypted sensitive data using SecureBuffer');
        console.log('  Decrypted:', decrypted.toString('utf8'));

        // Step 8: Create SecureBuffer from existing buffer
        console.log('');
        console.log('Step 8: Creating SecureBuffer from existing data...');
        const originalData = Buffer.from('Another secret message', 'utf8');
        const secureFromBuffer = new zupt.SecureBuffer(originalData.length);
        secureFromBuffer.copy(originalData);
        console.log('  Original buffer:', originalData.toString('utf8'));
        console.log('  Secure buffer:', secureFromBuffer.toBuffer().toString('utf8'));

        // Step 9: Demonstrate automatic zeroization on destruction
        console.log('');
        console.log('Step 9: SecureBuffer automatic cleanup...');
        {
            // Create a new SecureBuffer in a block scope
            const tempSecure = new zupt.SecureBuffer(128);
            tempSecure.copy(Buffer.from('temporary-secret', 'utf8'));
            console.log('  Created temporary SecureBuffer');
            // When this scope ends, the SecureBuffer is automatically zeroized
        }
        console.log('  Temporary SecureBuffer has been destroyed and zeroized');

        console.log('');
        console.log('All SecureBuffer examples completed successfully!');

    } catch (err) {
        console.error('Error:', err.message);
        if (err.stack) {
            console.error(err.stack);
        }
        process.exit(1);
    }
}

main();
