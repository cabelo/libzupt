/*
 * libzupt - Node.js N-API Binding
 * Hybrid Post-Quantum Encryption (ML-KEM-768 + X25519)
 *
 * SPDX-License-Identifier: MIT
 */

/* Define NAPI_VERSION before including napi.h to ensure proper API selection */
#ifndef NAPI_VERSION
#define NAPI_VERSION 9
#endif

#include <napi.h>
#include "../include/zupt.hpp"

/* Helper to convert napi_value to std::vector<uint8_t> */
static std::vector<uint8_t> GetBufferAsVector(const Napi::Value& value) {
    Napi::Uint8Array arr = value.As<Napi::Uint8Array>();
    size_t length = arr.ByteLength();
    std::vector<uint8_t> data(length);
    memcpy(data.data(), arr.Data(), length);
    return data;
}

/* Helper to create a Buffer from vector */
static Napi::Value CreateBufferFromVector(Napi::Env env, const std::vector<uint8_t>& vec) {
    return Napi::Buffer<uint8_t>::Copy(env, vec.data(), vec.size());
}

/* ═══════════════════════════════════════════════════════════════════
 * SECURE BUFFER WRAPPER
 * ═══════════════════════════════════════════════════════════════════ */

class SecureBufferWrapper : public Napi::ObjectWrap<SecureBufferWrapper> {
public:
    static Napi::Object Init(Napi::Env env, Napi::Object exports);

    SecureBufferWrapper(const Napi::CallbackInfo& info);
    ~SecureBufferWrapper();

private:
    Napi::Value Zeroize(const Napi::CallbackInfo& info);
    Napi::Value ToBuffer(const Napi::CallbackInfo& info);
    Napi::Value Destroy(const Napi::CallbackInfo& info);
    Napi::Value GetSize(const Napi::CallbackInfo& info);
    Napi::Value GetDataLength(const Napi::CallbackInfo& info);

    std::unique_ptr<zupt::SecureBuffer> buffer_;
};

Napi::Object SecureBufferWrapper::Init(Napi::Env env, Napi::Object exports) {
    Napi::Function ctor = Napi::ObjectWrap<SecureBufferWrapper>::DefineClass(env, "SecureBuffer", {
        Napi::ObjectWrap<SecureBufferWrapper>::InstanceMethod("zeroize", &SecureBufferWrapper::Zeroize),
        Napi::ObjectWrap<SecureBufferWrapper>::InstanceMethod("toBuffer", &SecureBufferWrapper::ToBuffer),
        Napi::ObjectWrap<SecureBufferWrapper>::InstanceMethod("destroy", &SecureBufferWrapper::Destroy),
        Napi::ObjectWrap<SecureBufferWrapper>::InstanceAccessor("size",
            &SecureBufferWrapper::GetSize,
            nullptr),
        Napi::ObjectWrap<SecureBufferWrapper>::InstanceAccessor("dataLength",
            &SecureBufferWrapper::GetDataLength,
            nullptr)
    });

    exports.Set("SecureBuffer", ctor);
    return exports;
}

SecureBufferWrapper::SecureBufferWrapper(const Napi::CallbackInfo& info) : Napi::ObjectWrap<SecureBufferWrapper>(info) {
    uint32_t size = info[0].As<Napi::Number>().Uint32Value();
    buffer_ = std::make_unique<zupt::SecureBuffer>(size);
}

SecureBufferWrapper::~SecureBufferWrapper() = default;

Napi::Value SecureBufferWrapper::Zeroize(const Napi::CallbackInfo& info) {
    if (buffer_) {
        buffer_->zeroize();
    }
    return info.Env().Undefined();
}

Napi::Value SecureBufferWrapper::ToBuffer(const Napi::CallbackInfo& info) {
    if (!buffer_) {
        throw Napi::Error::New(info.Env(), "SecureBuffer has been destroyed");
    }
    std::vector<uint8_t> data = buffer_->toVector();
    return Napi::Buffer<uint8_t>::Copy(info.Env(), data.data(), data.size());
}

Napi::Value SecureBufferWrapper::Destroy(const Napi::CallbackInfo& info) {
    buffer_.reset();
    return info.Env().Undefined();
}

Napi::Value SecureBufferWrapper::GetSize(const Napi::CallbackInfo& info) {
    if (buffer_) {
        return Napi::Number::New(info.Env(), buffer_->size());
    }
    return Napi::Number::New(info.Env(), 0);
}

Napi::Value SecureBufferWrapper::GetDataLength(const Napi::CallbackInfo& info) {
    if (buffer_) {
        return Napi::Number::New(info.Env(), buffer_->size());
    }
    return Napi::Number::New(info.Env(), 0);
}

/* ═══════════════════════════════════════════════════════════════════
 * KEY GENERATOR WRAPPER
 * ═══════════════════════════════════════════════════════════════════ */

class KeyGeneratorWrapper : public Napi::ObjectWrap<KeyGeneratorWrapper> {
public:
    static Napi::Object Init(Napi::Env env, Napi::Object exports);

    KeyGeneratorWrapper(const Napi::CallbackInfo& info);
    ~KeyGeneratorWrapper();

private:
    Napi::Value GenerateKeyPair(const Napi::CallbackInfo& info);
    Napi::Value SaveKeyPair(const Napi::CallbackInfo& info);
    Napi::Value LoadKeyPair(const Napi::CallbackInfo& info);
    Napi::Value ExportPublicKey(const Napi::CallbackInfo& info);
    Napi::Value LoadPublicKey(const Napi::CallbackInfo& info);

    std::unique_ptr<zupt::KeyGenerator> keyGen_;
};

Napi::Object KeyGeneratorWrapper::Init(Napi::Env env, Napi::Object exports) {
    Napi::Function ctor = Napi::ObjectWrap<KeyGeneratorWrapper>::DefineClass(env, "KeyGenerator", {
        Napi::ObjectWrap<KeyGeneratorWrapper>::InstanceMethod("generateKeyPair", &KeyGeneratorWrapper::GenerateKeyPair),
        Napi::ObjectWrap<KeyGeneratorWrapper>::InstanceMethod("saveKeyPair", &KeyGeneratorWrapper::SaveKeyPair),
        Napi::ObjectWrap<KeyGeneratorWrapper>::InstanceMethod("loadKeyPair", &KeyGeneratorWrapper::LoadKeyPair),
        Napi::ObjectWrap<KeyGeneratorWrapper>::InstanceMethod("exportPublicKey", &KeyGeneratorWrapper::ExportPublicKey),
        Napi::ObjectWrap<KeyGeneratorWrapper>::InstanceMethod("loadPublicKey", &KeyGeneratorWrapper::LoadPublicKey)
    });

    exports.Set("KeyGenerator", ctor);
    return exports;
}

KeyGeneratorWrapper::KeyGeneratorWrapper(const Napi::CallbackInfo& info) : Napi::ObjectWrap<KeyGeneratorWrapper>(info) {
    keyGen_ = std::make_unique<zupt::KeyGenerator>();
}

KeyGeneratorWrapper::~KeyGeneratorWrapper() = default;

Napi::Value KeyGeneratorWrapper::GenerateKeyPair(const Napi::CallbackInfo& info) {
    if (!keyGen_) {
        throw Napi::Error::New(info.Env(), "KeyGenerator has been destroyed");
    }

    zupt::KeyPair kp = keyGen_->generateKeyPair();

    Napi::Object result = Napi::Object::New(info.Env());
    result.Set("publicKey", Napi::Buffer<uint8_t>::Copy(info.Env(), kp.public_key.data(), kp.public_key.size()));
    result.Set("secretKey", Napi::Buffer<uint8_t>::Copy(info.Env(), kp.secret_key.data(), kp.secret_key.size()));

    zupt::secureWipe(kp.public_key.data(), kp.public_key.size());
    zupt::secureWipe(kp.secret_key.data(), kp.secret_key.size());

    return result;
}

Napi::Value KeyGeneratorWrapper::SaveKeyPair(const Napi::CallbackInfo& info) {
    if (!keyGen_) {
        throw Napi::Error::New(info.Env(), "KeyGenerator has been destroyed");
    }

    Napi::Object keypair = info[0].As<Napi::Object>();
    std::string filename = info[1].As<Napi::String>();

    Napi::Uint8Array pubArray = keypair.Get("publicKey").As<Napi::Uint8Array>();
    Napi::Uint8Array privArray = keypair.Get("secretKey").As<Napi::Uint8Array>();

    std::vector<uint8_t> publicKey(pubArray.ByteLength());
    std::vector<uint8_t> secretKey(privArray.ByteLength());

    memcpy(publicKey.data(), pubArray.Data(), publicKey.size());
    memcpy(secretKey.data(), privArray.Data(), secretKey.size());

    zupt::KeyPair kp(publicKey, secretKey);
    keyGen_->saveKeyPair(kp, filename);

    zupt::secureWipe(publicKey.data(), publicKey.size());
    zupt::secureWipe(secretKey.data(), secretKey.size());

    return info.Env().Undefined();
}

Napi::Value KeyGeneratorWrapper::LoadKeyPair(const Napi::CallbackInfo& info) {
    if (!keyGen_) {
        throw Napi::Error::New(info.Env(), "KeyGenerator has been destroyed");
    }

    std::string filename = info[0].As<Napi::String>();
    zupt::KeyPair kp = keyGen_->loadKeyPair(filename);

    Napi::Object result = Napi::Object::New(info.Env());
    result.Set("publicKey", Napi::Buffer<uint8_t>::Copy(info.Env(), kp.public_key.data(), kp.public_key.size()));
    result.Set("secretKey", Napi::Buffer<uint8_t>::Copy(info.Env(), kp.secret_key.data(), kp.secret_key.size()));

    return result;
}

Napi::Value KeyGeneratorWrapper::ExportPublicKey(const Napi::CallbackInfo& info) {
    if (!keyGen_) {
        throw Napi::Error::New(info.Env(), "KeyGenerator has been destroyed");
    }

    std::string privfile = info[0].As<Napi::String>();
    std::string pubfile = info[1].As<Napi::String>();
    keyGen_->exportPublicKey(privfile, pubfile);
    return info.Env().Undefined();
}

Napi::Value KeyGeneratorWrapper::LoadPublicKey(const Napi::CallbackInfo& info) {
    if (!keyGen_) {
        throw Napi::Error::New(info.Env(), "KeyGenerator has been destroyed");
    }

    std::string filename = info[0].As<Napi::String>();
    std::vector<uint8_t> publicKey = keyGen_->loadPublicKey(filename);

    return Napi::Buffer<uint8_t>::Copy(info.Env(), publicKey.data(), publicKey.size());
}

/* ═══════════════════════════════════════════════════════════════════
 * ENCRYPTOR WRAPPER
 * ═══════════════════════════════════════════════════════════════════ */

class EncryptorWrapper : public Napi::ObjectWrap<EncryptorWrapper> {
public:
    static Napi::Object Init(Napi::Env env, Napi::Object exports);

    EncryptorWrapper(const Napi::CallbackInfo& info);
    ~EncryptorWrapper();

private:
    Napi::Value EncryptMemory(const Napi::CallbackInfo& info);
    Napi::Value EncryptFile(const Napi::CallbackInfo& info);
    static Napi::Value GetEncryptionHeaderSize(const Napi::CallbackInfo& info);

    std::unique_ptr<zupt::Encryptor> encryptor_;
};

Napi::Object EncryptorWrapper::Init(Napi::Env env, Napi::Object exports) {
    Napi::Function ctor = Napi::ObjectWrap<EncryptorWrapper>::DefineClass(env, "Encryptor", {
        Napi::ObjectWrap<EncryptorWrapper>::InstanceMethod("encryptMemory", &EncryptorWrapper::EncryptMemory),
        Napi::ObjectWrap<EncryptorWrapper>::InstanceMethod("encryptFile", &EncryptorWrapper::EncryptFile),
        Napi::ObjectWrap<EncryptorWrapper>::StaticMethod("getEncryptionHeaderSize", &EncryptorWrapper::GetEncryptionHeaderSize)
    });

    exports.Set("Encryptor", ctor);
    return exports;
}

EncryptorWrapper::EncryptorWrapper(const Napi::CallbackInfo& info) : Napi::ObjectWrap<EncryptorWrapper>(info) {
    Napi::Uint8Array pubArray = info[0].As<Napi::Uint8Array>();
    std::vector<uint8_t> publicKey(pubArray.ByteLength());
    memcpy(publicKey.data(), pubArray.Data(), publicKey.size());
    encryptor_ = std::make_unique<zupt::Encryptor>(publicKey);
}

EncryptorWrapper::~EncryptorWrapper() = default;

Napi::Value EncryptorWrapper::EncryptMemory(const Napi::CallbackInfo& info) {
    if (!encryptor_) {
        throw Napi::Error::New(info.Env(), "Encryptor has been destroyed");
    }

    Napi::Uint8Array dataArray = info[0].As<Napi::Uint8Array>();
    std::vector<uint8_t> data(dataArray.ByteLength());
    memcpy(data.data(), dataArray.Data(), data.size());

    auto [ciphertext, encHeader] = encryptor_->encryptMemory(data);

    Napi::Object result = Napi::Object::New(info.Env());
    result.Set("ciphertext", Napi::Buffer<uint8_t>::Copy(info.Env(), ciphertext.data(), ciphertext.size()));
    result.Set("encHeader", Napi::Buffer<uint8_t>::Copy(info.Env(), encHeader.data(), encHeader.size()));

    return result;
}

Napi::Value EncryptorWrapper::EncryptFile(const Napi::CallbackInfo& info) {
    if (!encryptor_) {
        throw Napi::Error::New(info.Env(), "Encryptor has been destroyed");
    }

    std::string filename = info[0].As<Napi::String>();
    auto [ciphertext, encHeader] = encryptor_->encryptFile(filename);

    Napi::Object result = Napi::Object::New(info.Env());
    result.Set("ciphertext", Napi::Buffer<uint8_t>::Copy(info.Env(), ciphertext.data(), ciphertext.size()));
    result.Set("encHeader", Napi::Buffer<uint8_t>::Copy(info.Env(), encHeader.data(), encHeader.size()));

    return result;
}

Napi::Value EncryptorWrapper::GetEncryptionHeaderSize(const Napi::CallbackInfo& info) {
    return Napi::Number::New(info.Env(), zupt::Encryptor::getEncryptionHeaderSize());
}

/* ═══════════════════════════════════════════════════════════════════
 * DECRYPTOR WRAPPER
 * ═══════════════════════════════════════════════════════════════════ */

class DecryptorWrapper : public Napi::ObjectWrap<DecryptorWrapper> {
public:
    static Napi::Object Init(Napi::Env env, Napi::Object exports);

    DecryptorWrapper(const Napi::CallbackInfo& info);
    ~DecryptorWrapper();

private:
    Napi::Value DecryptMemory(const Napi::CallbackInfo& info);
    Napi::Value DecryptFile(const Napi::CallbackInfo& info);

    std::unique_ptr<zupt::Decryptor> decryptor_;
};

Napi::Object DecryptorWrapper::Init(Napi::Env env, Napi::Object exports) {
    Napi::Function ctor = Napi::ObjectWrap<DecryptorWrapper>::DefineClass(env, "Decryptor", {
        Napi::ObjectWrap<DecryptorWrapper>::InstanceMethod("decryptMemory", &DecryptorWrapper::DecryptMemory),
        Napi::ObjectWrap<DecryptorWrapper>::InstanceMethod("decryptFile", &DecryptorWrapper::DecryptFile)
    });

    exports.Set("Decryptor", ctor);
    return exports;
}

DecryptorWrapper::DecryptorWrapper(const Napi::CallbackInfo& info) : Napi::ObjectWrap<DecryptorWrapper>(info) {
    Napi::Uint8Array privArray = info[0].As<Napi::Uint8Array>();
    std::vector<uint8_t> privateKey(privArray.ByteLength());
    memcpy(privateKey.data(), privArray.Data(), privateKey.size());
    decryptor_ = std::make_unique<zupt::Decryptor>(privateKey);
}

DecryptorWrapper::~DecryptorWrapper() = default;

Napi::Value DecryptorWrapper::DecryptMemory(const Napi::CallbackInfo& info) {
    if (!decryptor_) {
        throw Napi::Error::New(info.Env(), "Decryptor has been destroyed");
    }

    Napi::Uint8Array ciphertextArray = info[0].As<Napi::Uint8Array>();
    Napi::Uint8Array encHeaderArray = info[1].As<Napi::Uint8Array>();

    std::vector<uint8_t> ciphertext(ciphertextArray.ByteLength());
    std::vector<uint8_t> encHeader(encHeaderArray.ByteLength());

    memcpy(ciphertext.data(), ciphertextArray.Data(), ciphertext.size());
    memcpy(encHeader.data(), encHeaderArray.Data(), encHeader.size());

    std::vector<uint8_t> plaintext = decryptor_->decryptMemory(ciphertext, encHeader);

    return Napi::Buffer<uint8_t>::Copy(info.Env(), plaintext.data(), plaintext.size());
}

Napi::Value DecryptorWrapper::DecryptFile(const Napi::CallbackInfo& info) {
    if (!decryptor_) {
        throw Napi::Error::New(info.Env(), "Decryptor has been destroyed");
    }

    std::string filename = info[0].As<Napi::String>();
    Napi::Uint8Array encHeaderArray = info[1].As<Napi::Uint8Array>();

    std::vector<uint8_t> encHeader(encHeaderArray.ByteLength());
    memcpy(encHeader.data(), encHeaderArray.Data(), encHeader.size());

    std::vector<uint8_t> plaintext = decryptor_->decryptFile(filename, encHeader);

    return Napi::Buffer<uint8_t>::Copy(info.Env(), plaintext.data(), plaintext.size());
}

/* ═══════════════════════════════════════════════════════════════════
 * MODULE INITIALIZATION
 * ═══════════════════════════════════════════════════════════════════ */

Napi::Value RandomBytes(const Napi::CallbackInfo& info) {
    uint32_t size = info[0].As<Napi::Number>().Uint32Value();
    std::vector<uint8_t> bytes = zupt::randomBytes(size);
    return Napi::Buffer<uint8_t>::Copy(info.Env(), bytes.data(), bytes.size());
}

Napi::Value GetVersion(const Napi::CallbackInfo& info) {
    return Napi::String::New(info.Env(), zupt::getVersion());
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    SecureBufferWrapper::Init(env, exports);
    KeyGeneratorWrapper::Init(env, exports);
    EncryptorWrapper::Init(env, exports);
    DecryptorWrapper::Init(env, exports);

    exports.Set("randomBytes", Napi::Function::New(env, RandomBytes));
    exports.Set("getVersion", Napi::Function::New(env, GetVersion));

    return exports;
}

NODE_API_MODULE(zupt_napi, Init)
