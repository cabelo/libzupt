/*
 * libzupt - Node.js Wrapper
 * Loads native addon when available, falls back only if native load fails.
 */

const fs = require('fs');
const path = require('path');

let native = null;
let nativeLoadError = null;

// Tenta carregar o addon nativo compilado
try {
    native = require(path.join(__dirname, 'build', 'Release', 'zupt.node'));
} catch (err) {
    nativeLoadError = err;
}

// Se conseguiu carregar o nativo, exporta ele diretamente
if (native) {
    module.exports = native;
    return;
}

/**
 * Fallback JS apenas para documentação / desenvolvimento
 * Não faz criptografia real.
 */

class SecureBuffer {
    constructor(size) {
        if (typeof size !== 'number' || size <= 0) {
            throw new Error('SecureBuffer requires a positive size');
        }
        this._buffer = Buffer.alloc(size);
        this._size = size;
        this._dataLen = 0;
    }

    zeroize() {
        if (this._buffer && this._size > 0) {
            const crypto = require('crypto');
            crypto.randomBytes(this._size).copy(this._buffer);
            this._buffer.fill(0);
            this._dataLen = 0;
        }
    }

    get size() {
        return this._size;
    }

    get dataLength() {
        return this._dataLen;
    }

    copy(data) {
        if (!Buffer.isBuffer(data)) {
            data = Buffer.from(data);
        }
        const copyLen = Math.min(data.length, this._size);
        data.copy(this._buffer, 0, 0, copyLen);
        this._dataLen = copyLen;
    }

    toBuffer() {
        return Buffer.from(this._buffer.slice(0, this._dataLen));
    }

    toFullBuffer() {
        return Buffer.from(this._buffer);
    }

    destroy() {
        this.zeroize();
        this._buffer = null;
        this._size = 0;
        this._dataLen = 0;
    }
}

class KeyGenerator {
    generateKeyPair() {
        throw new Error(
            'Native addon not loaded. Cannot generate real key pairs.\n' +
            `Load error: ${nativeLoadError ? nativeLoadError.message : 'unknown'}`
        );
    }
}

class Encryptor {
    constructor(publicKey) {
        this._publicKey = publicKey;
    }

    encryptMemory(data) {
        throw new Error(
            'Native addon not loaded. Cannot perform real encryption.\n' +
            `Load error: ${nativeLoadError ? nativeLoadError.message : 'unknown'}`
        );
    }

    encryptFile(filename) {
        const data = fs.readFileSync(filename);
        return this.encryptMemory(data);
    }

    static getEncryptionHeaderSize() {
        return 1137;
    }
}

class Decryptor {
    constructor(privateKey) {
        this._privateKey = privateKey;
    }

    decryptMemory(ciphertext, encHeader) {
        throw new Error(
            'Native addon not loaded. Cannot perform real decryption.\n' +
            `Load error: ${nativeLoadError ? nativeLoadError.message : 'unknown'}`
        );
    }

    decryptFile(filename, encHeader) {
        const ciphertext = fs.readFileSync(filename);
        return this.decryptMemory(ciphertext, encHeader);
    }

    decryptMemorySecure(ciphertext, encHeader) {
        const decrypted = this.decryptMemory(ciphertext, encHeader);
        const secureBuf = new SecureBuffer(decrypted.length);
        decrypted.copy(secureBuf._buffer);
        return secureBuf;
    }
}

function randomBytes(size) {
    const crypto = require('crypto');
    return crypto.randomBytes(size);
}

function getVersion() {
    return '2.1.5';
}

module.exports = {
    SecureBuffer,
    KeyGenerator,
    Encryptor,
    Decryptor,
    randomBytes,
    getVersion,
    nativeLoadError
};
