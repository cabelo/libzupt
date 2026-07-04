/*
 * libzupt - File Encryption Example (Node.js)
 * Shows how to encrypt and decrypt files
 *
 * SPDX-License-Identifier: MIT
 */

const zupt = require('./index');
const fs = require('fs');
const path = require('path');

function printUsage() {
    console.log('Usage:');
    console.log('  node example_file.js genkey <private_key_file> [public_key_file]');
    console.log('  node example_file.js encrypt <public_key_file> <input_file> <output_file>');
    console.log('  node example_file.js decrypt <private_key_file> <input_file.zupt> <output_file> [header_file]');
    console.log('');
    console.log('Examples:');
    console.log('  node example_file.js genkey key.pem');
    console.log('  node example_file.js encrypt key.pem.pub input.txt encrypted.zupt');
    console.log('  node example_file.js decrypt key.pem encrypted.zupt decrypted.txt');
}

function main() {
    if (process.argv.length < 3) {
        printUsage();
        process.exit(1);
    }

    const command = process.argv[2];

    try {
        switch (command) {
            case 'genkey': {
                if (process.argv.length < 4) {
                    throw new Error('Missing private key file argument');
                }

                const privKeyFile = process.argv[3];
                const pubKeyFile = process.argv[4] || privKeyFile.replace('.key', '.pub.key');

                console.log('Generating key pair...');
                const keygen = new zupt.KeyGenerator();
                const keypair = keygen.generateKeyPair();

                keygen.saveKeyPair(keypair, privKeyFile);
                keygen.exportPublicKey(privKeyFile, pubKeyFile);

                console.log('Private key saved to:', privKeyFile);
                console.log('Public key saved to:', pubKeyFile);
                console.log('Public key size:', keypair.publicKey.length, 'bytes');
                console.log('Private key size:', keypair.secretKey.length, 'bytes');
                break;
            }

            case 'encrypt': {
                if (process.argv.length < 6) {
                    throw new Error('Missing arguments for encrypt');
                }

                const pubKeyFile = process.argv[3];
                const inputFile = process.argv[4];
                const outputFile = process.argv[5];

                if (!fs.existsSync(pubKeyFile)) {
                    throw new Error('Public key file not found: ' + pubKeyFile);
                }
                if (!fs.existsSync(inputFile)) {
                    throw new Error('Input file not found: ' + inputFile);
                }

                console.log('Loading public key from:', pubKeyFile);
                const keygen = new zupt.KeyGenerator();
                const publicKey = keygen.loadPublicKey(pubKeyFile);

                console.log('Loading file:', inputFile);
                const data = fs.readFileSync(inputFile);
                console.log('File size:', data.length, 'bytes');

                console.log('Encrypting...');
                const encryptor = new zupt.Encryptor(publicKey);
                const { ciphertext, encHeader } = encryptor.encryptFile(inputFile);

                fs.writeFileSync(outputFile, ciphertext);
                const headerFile = outputFile + '.header';
                fs.writeFileSync(headerFile, encHeader);

                console.log('Encrypted file saved to:', outputFile);
                console.log('Encryption header saved to:', headerFile);
                console.log('Encrypted size:', ciphertext.length, 'bytes');
                console.log('Header size:', encHeader.length, 'bytes');
                break;
            }

            case 'decrypt': {
                if (process.argv.length < 6) {
                    throw new Error('Missing arguments for decrypt');
                }

                const privKeyFile = process.argv[3];
                const inputFile = process.argv[4];
                const outputFile = process.argv[5];
                const headerFile = process.argv[6] || inputFile + '.header';

                if (!fs.existsSync(privKeyFile)) {
                    throw new Error('Private key file not found: ' + privKeyFile);
                }
                if (!fs.existsSync(inputFile)) {
                    throw new Error('Input file not found: ' + inputFile);
                }
                if (!fs.existsSync(headerFile)) {
                    throw new Error('Header file not found: ' + headerFile);
                }

                console.log('Loading private key from:', privKeyFile);
                const keygen = new zupt.KeyGenerator();
                const keypair = keygen.loadKeyPair(privKeyFile);

                console.log('Loading encrypted file:', inputFile);
                const ciphertext = fs.readFileSync(inputFile);

                console.log('Loading encryption header:', headerFile);
                const encHeader = fs.readFileSync(headerFile);

                console.log('Decrypting...');
                const decryptor = new zupt.Decryptor(keypair.secretKey);
                const decrypted = decryptor.decryptFile(inputFile, encHeader);

                fs.writeFileSync(outputFile, decrypted);

                console.log('Decrypted file saved to:', outputFile);
                console.log('Decrypted size:', decrypted.length, 'bytes');

                // Show first 200 bytes as preview
                if (decrypted.length > 0) {
                    const previewLen = Math.min(200, decrypted.length);
                    console.log('Preview:', decrypted.toString('utf8', 0, previewLen));
                    if (decrypted.length > 200) {
                        console.log('... (truncated)');
                    }
                }
                break;
            }

            case 'test': {
                // Run a complete test: generate keys, encrypt, decrypt
                console.log('Running complete encryption/decryption test...');

                const testDir = '/tmp/libzupt_file_test';
                fs.mkdirSync(testDir, { recursive: true });

                const privKeyFile = path.join(testDir, 'test.key');
                const pubKeyFile = path.join(testDir, 'test.pub.key');
                const inputFile = path.join(testDir, 'test_input.txt');
                const encryptedFile = path.join(testDir, 'test_encrypted.zupt');
                const decryptedFile = path.join(testDir, 'test_decrypted.txt');

                // Create test file with some content
                const testContent = 'This is a test file.\nLine 2: Special chars: !@#$%^&*()\n';
                fs.writeFileSync(inputFile, testContent);

                // Generate keys
                console.log('Step 1: Generating keys...');
                const keygen = new zupt.KeyGenerator();
                const keypair = keygen.generateKeyPair();
                keygen.saveKeyPair(keypair, privKeyFile);
                keygen.exportPublicKey(privKeyFile, pubKeyFile);

                // Encrypt
                console.log('Step 2: Encrypting file...');
                const publicKey = keygen.loadPublicKey(pubKeyFile);
                const encryptor = new zupt.Encryptor(publicKey);
                const { ciphertext, encHeader } = encryptor.encryptFile(inputFile);
                fs.writeFileSync(encryptedFile, ciphertext);
                fs.writeFileSync(encryptedFile + '.header', encHeader);

                // Decrypt
                console.log('Step 3: Decrypting file...');
                const keypair2 = keygen.loadKeyPair(privKeyFile);
                const decryptor = new zupt.Decryptor(keypair2.secretKey);
                const decrypted = decryptor.decryptFile(encryptedFile, encHeader);

                // Verify
                console.log('Step 4: Verifying...');
                const decryptedContent = decrypted.toString('utf8');
                if (decryptedContent === testContent) {
                    console.log('SUCCESS: File encryption/decryption test passed!');
                } else {
                    console.log('ERROR: Decrypted content does not match!');
                    console.log('Expected:', testContent);
                    console.log('Got:', decryptedContent);
                }

                // Cleanup
                fs.unlinkSync(inputFile);
                fs.unlinkSync(encryptedFile);
                fs.unlinkSync(encryptedFile + '.header');
                fs.unlinkSync(privKeyFile);
                fs.unlinkSync(pubKeyFile);
                fs.rmdirSync(testDir);

                break;
            }

            default:
                console.error('Unknown command:', command);
                printUsage();
                process.exit(1);
        }
    } catch (err) {
        console.error('Error:', err.message);
        if (err.stack) {
            console.error(err.stack);
        }
        process.exit(1);
    }
}

main();
