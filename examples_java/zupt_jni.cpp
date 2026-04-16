/*
 * libzupt - Java Native Interface (JNI) bindings
 * SPDX-License-Identifier: MIT
 */

#include <jni.h>
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>

#include "zupt.hpp"

// Exception class for ZuptError
static jclass zuptErrorClass = nullptr;

// Helper function to throw Java exception from C++ exception
void throwJavaException(JNIEnv* env, const std::exception& e) {
    // Cache zuptErrorClass if not already done
    if (!zuptErrorClass) {
        // Try to find the class - if this fails, use RuntimeException
        jclass exClass = env->FindClass("com/libzupt/ZuptError");
        if (exClass) {
            zuptErrorClass = (jclass)env->NewGlobalRef(exClass);
            env->DeleteLocalRef(exClass);
        }
    }

    if (zuptErrorClass) {
        env->ThrowNew(zuptErrorClass, e.what());
    } else {
        // Fallback to RuntimeException if ZuptError not found
        jclass runtimeExClass = env->FindClass("java/lang/RuntimeException");
        if (runtimeExClass) {
            env->ThrowNew(runtimeExClass, e.what());
            env->DeleteLocalRef(runtimeExClass);
        } else {
            // Ultimate fallback - can't throw proper exception
            const char* msg = e.what();
            if (!msg) msg = "Unknown error";
            env->ThrowNew(env->FindClass("java/lang/Error"), msg);
        }
    }
}

// Convert jbyteArray to std::vector<uint8_t>
std::vector<uint8_t> jbyteArrayToVector(JNIEnv* env, jbyteArray arr) {
    jsize len = env->GetArrayLength(arr);
    std::vector<uint8_t> vec(len);
    env->GetByteArrayRegion(arr, 0, len, reinterpret_cast<jbyte*>(vec.data()));
    return vec;
}

// Convert std::vector<uint8_t> to jbyteArray
jbyteArray vectorToJByteArray(JNIEnv* env, const std::vector<uint8_t>& vec) {
    jsize len = vec.size();
    jbyteArray arr = env->NewByteArray(len);
    env->SetByteArrayRegion(arr, 0, len, const_cast<jbyte*>(reinterpret_cast<const jbyte*>(vec.data())));
    return arr;
}

// KeyPair class
static jclass keyPairClass = nullptr;
static jfieldID publicKeyField = nullptr;
static jfieldID secretKeyField = nullptr;

jobject createKeyPair(JNIEnv* env, const zupt::KeyPair& kp) {
    if (!keyPairClass) {
        jclass cls = env->FindClass("com/libzupt/KeyPair");
        if (cls) {
            keyPairClass = (jclass)env->NewGlobalRef(cls);
            publicKeyField = env->GetFieldID(keyPairClass, "publicKey", "[B");
            secretKeyField = env->GetFieldID(keyPairClass, "secretKey", "[B");
        }
    }

    jobject result = env->NewObject(keyPairClass, env->GetMethodID(keyPairClass, "<init>", "()V"));
    env->SetObjectField(result, publicKeyField, vectorToJByteArray(env, kp.public_key));
    env->SetObjectField(result, secretKeyField, vectorToJByteArray(env, kp.secret_key));
    return result;
}

// Forward declarations for native methods
JNIEXPORT jobject JNICALL Java_com_libzupt_KeyGenerator_generateKeyPair(JNIEnv*, jobject);
JNIEXPORT jobject JNICALL Java_com_libzupt_KeyGenerator_loadKeyPair(JNIEnv*, jobject, jstring);
JNIEXPORT jbyteArray JNICALL Java_com_libzupt_KeyGenerator_loadPublicKey(JNIEnv*, jobject, jstring);
JNIEXPORT void JNICALL Java_com_libzupt_KeyGenerator_exportPublicKey(JNIEnv*, jobject, jstring, jstring);
JNIEXPORT void JNICALL Java_com_libzupt_KeyGenerator_saveKeyPair(JNIEnv*, jobject, jobject, jstring);
JNIEXPORT jobject JNICALL Java_com_libzupt_Encryptor_nativeEncryptMemory(JNIEnv*, jobject, jbyteArray);
JNIEXPORT jobject JNICALL Java_com_libzupt_Encryptor_nativeEncryptMemorySecure(JNIEnv*, jobject, jbyteArray);
JNIEXPORT jobject JNICALL Java_com_libzupt_Encryptor_nativeEncryptFile(JNIEnv*, jobject, jstring);
JNIEXPORT jbyteArray JNICALL Java_com_libzupt_Decryptor_decryptMemoryNative(JNIEnv*, jobject, jbyteArray, jbyteArray);
JNIEXPORT jbyteArray JNICALL Java_com_libzupt_Decryptor_decryptFileNative(JNIEnv*, jobject, jstring, jbyteArray);
JNIEXPORT jbyteArray JNICALL Java_com_libzupt_NativeLib_randomBytes(JNIEnv*, jobject, jint);
JNIEXPORT jbyteArray JNICALL Java_com_libzupt_NativeLib_sha256(JNIEnv*, jobject, jbyteArray);
JNIEXPORT jbyteArray JNICALL Java_com_libzupt_NativeLib_sha3512(JNIEnv*, jobject, jbyteArray);

// Native method declarations
static JNINativeMethod keyGenMethods[] = {
    {"generateKeyPair", "()Lcom/libzupt/KeyPair;", (void*)Java_com_libzupt_KeyGenerator_generateKeyPair},
    {"loadKeyPair", "(Ljava/lang/String;)Lcom/libzupt/KeyPair;", (void*)Java_com_libzupt_KeyGenerator_loadKeyPair},
    {"loadPublicKey", "(Ljava/lang/String;)[B", (void*)Java_com_libzupt_KeyGenerator_loadPublicKey},
    {"exportPublicKey", "(Ljava/lang/String;Ljava/lang/String;)V", (void*)Java_com_libzupt_KeyGenerator_exportPublicKey},
    {"saveKeyPair", "(Lcom/libzupt/KeyPair;Ljava/lang/String;)V", (void*)Java_com_libzupt_KeyGenerator_saveKeyPair}
};

static JNINativeMethod encryptorMethods[] = {
    {"nativeEncryptMemory", "([B)[Ljava/lang/Object;", (void*)Java_com_libzupt_Encryptor_nativeEncryptMemory},
    {"nativeEncryptFile", "(Ljava/lang/String;)[Ljava/lang/Object;", (void*)Java_com_libzupt_Encryptor_nativeEncryptFile}
};

static JNINativeMethod decryptorMethods[] = {
    {"decryptMemoryNative", "([B[B)[B", (void*)Java_com_libzupt_Decryptor_decryptMemoryNative},
    {"decryptFileNative", "(Ljava/lang/String;[B)[B", (void*)Java_com_libzupt_Decryptor_decryptFileNative}
};

static JNINativeMethod nativeLibMethods[] = {
    {"randomBytes", "(I)[B", (void*)Java_com_libzupt_NativeLib_randomBytes},
    {"sha256", "([B)[B", (void*)Java_com_libzupt_NativeLib_sha256},
    {"sha3512", "([B)[B", (void*)Java_com_libzupt_NativeLib_sha3512}
};

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* /* reserved */) {
    JNIEnv* env;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_8) != JNI_OK) {
        return JNI_ERR;
    }

    // Register native methods for KeyGenerator
    jclass keyGenClass = env->FindClass("com/libzupt/KeyGenerator");
    if (keyGenClass && env->RegisterNatives(keyGenClass, keyGenMethods, 5) < 0) {
        return JNI_ERR;
    }

    // Register native methods for Encryptor
    jclass encryptClass = env->FindClass("com/libzupt/Encryptor");
    if (encryptClass && env->RegisterNatives(encryptClass, encryptorMethods, 2) < 0) {
        return JNI_ERR;
    }

    // Register native methods for Decryptor
    jclass decryptClass = env->FindClass("com/libzupt/Decryptor");
    if (decryptClass && env->RegisterNatives(decryptClass, decryptorMethods, 2) < 0) {
        return JNI_ERR;
    }

    // Register native methods for NativeLib (helpers)
    jclass nativeLibClass = env->FindClass("com/libzupt/NativeLib");
    if (nativeLibClass && env->RegisterNatives(nativeLibClass, nativeLibMethods, 3) < 0) {
        return JNI_ERR;
    }

    return JNI_VERSION_1_8;
}

// KeyGenerator native methods
JNIEXPORT jobject JNICALL Java_com_libzupt_KeyGenerator_generateKeyPair(JNIEnv* env, jobject /* self */) {
    try {
        zupt::KeyGenerator kg;
        zupt::KeyPair kp = kg.generateKeyPair();
        return createKeyPair(env, kp);
    } catch (const std::exception& e) {
        throwJavaException(env, e);
        return nullptr;
    }
}

JNIEXPORT jobject JNICALL Java_com_libzupt_KeyGenerator_loadKeyPair(JNIEnv* env, jobject /* self */, jstring jfilename) {
    try {
        const char* filename = env->GetStringUTFChars(jfilename, nullptr);
        zupt::KeyGenerator kg;
        zupt::KeyPair kp = kg.loadKeyPair(filename);
        env->ReleaseStringUTFChars(jfilename, filename);
        return createKeyPair(env, kp);
    } catch (const std::exception& e) {
        throwJavaException(env, e);
        return nullptr;
    }
}

JNIEXPORT jbyteArray JNICALL Java_com_libzupt_KeyGenerator_loadPublicKey(JNIEnv* env, jobject /* self */, jstring jfilename) {
    try {
        const char* filename = env->GetStringUTFChars(jfilename, nullptr);
        zupt::KeyGenerator kg;
        std::vector<uint8_t> publicKey = kg.loadPublicKey(filename);
        env->ReleaseStringUTFChars(jfilename, filename);
        return vectorToJByteArray(env, publicKey);
    } catch (const std::exception& e) {
        throwJavaException(env, e);
        return nullptr;
    }
}

JNIEXPORT void JNICALL Java_com_libzupt_KeyGenerator_exportPublicKey(JNIEnv* env, jobject /* self */, jstring jprivfile, jstring jpubfile) {
    try {
        const char* privfile = env->GetStringUTFChars(jprivfile, nullptr);
        const char* pubfile = env->GetStringUTFChars(jpubfile, nullptr);
        zupt::KeyGenerator kg;
        kg.exportPublicKey(privfile, pubfile);
        env->ReleaseStringUTFChars(jprivfile, privfile);
        env->ReleaseStringUTFChars(jpubfile, pubfile);
    } catch (const std::exception& e) {
        throwJavaException(env, e);
    }
}

JNIEXPORT void JNICALL Java_com_libzupt_KeyGenerator_saveKeyPair(JNIEnv* env, jobject /* self */, jobject jkeypair, jstring jfilename) {
    try {
        if (!keyPairClass) {
            keyPairClass = (jclass)env->NewGlobalRef(env->FindClass("com/libzupt/KeyPair"));
            publicKeyField = env->GetFieldID(keyPairClass, "publicKey", "[B");
            secretKeyField = env->GetFieldID(keyPairClass, "secretKey", "[B");
        }

        jbyteArray pubArray = (jbyteArray)env->GetObjectField(jkeypair, publicKeyField);
        jbyteArray privArray = (jbyteArray)env->GetObjectField(jkeypair, secretKeyField);

        std::vector<uint8_t> publicKey = jbyteArrayToVector(env, pubArray);
        std::vector<uint8_t> secretKey = jbyteArrayToVector(env, privArray);

        zupt::KeyPair kp;
        kp.public_key = std::move(publicKey);
        kp.secret_key = std::move(secretKey);

        const char* filename = env->GetStringUTFChars(jfilename, nullptr);
        zupt::KeyGenerator kg;
        kg.saveKeyPair(kp, filename);
        env->ReleaseStringUTFChars(jfilename, filename);
    } catch (const std::exception& e) {
        throwJavaException(env, e);
    }
}

// Encryptor native methods
JNIEXPORT jobject JNICALL Java_com_libzupt_Encryptor_nativeEncryptMemory(JNIEnv* env, jobject self, jbyteArray jdata) {
    try {
        std::vector<uint8_t> data = jbyteArrayToVector(env, jdata);

        jclass encryptorClass = env->GetObjectClass(self);
        jfieldID publicKeyField = env->GetFieldID(encryptorClass, "publicKey", "[B");
        jbyteArray pubArray = (jbyteArray)env->GetObjectField(self, publicKeyField);
        std::vector<uint8_t> publicKey = jbyteArrayToVector(env, pubArray);

        zupt::Encryptor encryptor(publicKey);
        auto result = encryptor.encryptMemory(data.data(), data.size());

        jobjectArray resultArray = env->NewObjectArray(2, env->FindClass("[B"), nullptr);
        env->SetObjectArrayElement(resultArray, 0, vectorToJByteArray(env, result.first));
        env->SetObjectArrayElement(resultArray, 1, vectorToJByteArray(env, result.second));
        return resultArray;
    } catch (const std::exception& e) {
        throwJavaException(env, e);
        return nullptr;
    }
}

JNIEXPORT jobject JNICALL Java_com_libzupt_Encryptor_nativeEncryptMemorySecure(JNIEnv* env, jobject self, jbyteArray jdata) {
    try {
        std::vector<uint8_t> data = jbyteArrayToVector(env, jdata);

        jclass encryptorClass = env->GetObjectClass(self);
        jfieldID publicKeyField = env->GetFieldID(encryptorClass, "publicKey", "[B");
        jbyteArray pubArray = (jbyteArray)env->GetObjectField(self, publicKeyField);
        std::vector<uint8_t> publicKey = jbyteArrayToVector(env, pubArray);

        zupt::Encryptor encryptor(publicKey);
        auto result = encryptor.encryptMemory(data.data(), data.size());

        jobjectArray resultArray = env->NewObjectArray(2, env->FindClass("[B"), nullptr);
        env->SetObjectArrayElement(resultArray, 0, vectorToJByteArray(env, result.first));
        env->SetObjectArrayElement(resultArray, 1, vectorToJByteArray(env, result.second));
        return resultArray;
    } catch (const std::exception& e) {
        throwJavaException(env, e);
        return nullptr;
    }
}

JNIEXPORT jobject JNICALL Java_com_libzupt_Encryptor_nativeEncryptFile(JNIEnv* env, jobject self, jstring jfilename) {
    try {
        const char* filename = env->GetStringUTFChars(jfilename, nullptr);

        jclass encryptorClass = env->GetObjectClass(self);
        jfieldID publicKeyField = env->GetFieldID(encryptorClass, "publicKey", "[B");
        jbyteArray pubArray = (jbyteArray)env->GetObjectField(self, publicKeyField);
        std::vector<uint8_t> publicKey = jbyteArrayToVector(env, pubArray);

        zupt::Encryptor encryptor(publicKey);
        auto result = encryptor.encryptFile(filename);
        env->ReleaseStringUTFChars(jfilename, filename);

        jobjectArray resultArray = env->NewObjectArray(2, env->FindClass("[B"), nullptr);
        env->SetObjectArrayElement(resultArray, 0, vectorToJByteArray(env, result.first));
        env->SetObjectArrayElement(resultArray, 1, vectorToJByteArray(env, result.second));
        return resultArray;
    } catch (const std::exception& e) {
        throwJavaException(env, e);
        return nullptr;
    }
}

// Decryptor native methods
JNIEXPORT jbyteArray JNICALL Java_com_libzupt_Decryptor_decryptMemoryNative(JNIEnv* env, jobject self, jbyteArray jciphertext, jbyteArray jheader) {
    try {
        std::vector<uint8_t> ciphertext = jbyteArrayToVector(env, jciphertext);
        std::vector<uint8_t> header = jbyteArrayToVector(env, jheader);

        jclass decryptorClass = env->GetObjectClass(self);
        jfieldID secretKeyField = env->GetFieldID(decryptorClass, "secretKey", "[B");
        jbyteArray privArray = (jbyteArray)env->GetObjectField(self, secretKeyField);
        std::vector<uint8_t> secretKey = jbyteArrayToVector(env, privArray);

        zupt::Decryptor decryptor(secretKey);
        std::vector<uint8_t> result = decryptor.decryptMemory(ciphertext.data(), ciphertext.size(), header);

        return vectorToJByteArray(env, result);
    } catch (const std::exception& e) {
        throwJavaException(env, e);
        return nullptr;
    }
}

JNIEXPORT jbyteArray JNICALL Java_com_libzupt_Decryptor_decryptMemorySecure(JNIEnv* env, jobject self, jbyteArray jciphertext, jbyteArray jheader) {
    try {
        std::vector<uint8_t> ciphertext = jbyteArrayToVector(env, jciphertext);
        std::vector<uint8_t> header = jbyteArrayToVector(env, jheader);

        jclass decryptorClass = env->GetObjectClass(self);
        jfieldID secretKeyField = env->GetFieldID(decryptorClass, "secretKey", "[B");
        jbyteArray privArray = (jbyteArray)env->GetObjectField(self, secretKeyField);
        std::vector<uint8_t> secretKey = jbyteArrayToVector(env, privArray);

        zupt::Decryptor decryptor(secretKey);
        zupt::SecureBuffer result = decryptor.decryptMemorySecure(ciphertext, header);

        return vectorToJByteArray(env, result.toVector());
    } catch (const std::exception& e) {
        throwJavaException(env, e);
        return nullptr;
    }
}

JNIEXPORT jbyteArray JNICALL Java_com_libzupt_Decryptor_decryptFileNative(JNIEnv* env, jobject self, jstring jfilename, jbyteArray jheader) {
    try {
        const char* filename = env->GetStringUTFChars(jfilename, nullptr);
        std::vector<uint8_t> header = jbyteArrayToVector(env, jheader);

        jclass decryptorClass = env->GetObjectClass(self);
        jfieldID secretKeyField = env->GetFieldID(decryptorClass, "secretKey", "[B");
        jbyteArray privArray = (jbyteArray)env->GetObjectField(self, secretKeyField);
        std::vector<uint8_t> secretKey = jbyteArrayToVector(env, privArray);

        zupt::Decryptor decryptor(secretKey);
        std::vector<uint8_t> result = decryptor.decryptFile(filename, header);
        env->ReleaseStringUTFChars(jfilename, filename);

        return vectorToJByteArray(env, result);
    } catch (const std::exception& e) {
        throwJavaException(env, e);
        return nullptr;
    }
}

// NativeLib helper methods
JNIEXPORT jbyteArray JNICALL Java_com_libzupt_NativeLib_randomBytes(JNIEnv* env, jobject /* self */, jint size) {
    try {
        std::vector<uint8_t> result = zupt::randomBytes(size);
        return vectorToJByteArray(env, result);
    } catch (const std::exception& e) {
        throwJavaException(env, e);
        return nullptr;
    }
}

JNIEXPORT jbyteArray JNICALL Java_com_libzupt_NativeLib_sha256(JNIEnv* env, jobject /* self */, jbyteArray jdata) {
    try {
        std::vector<uint8_t> data = jbyteArrayToVector(env, jdata);
        std::vector<uint8_t> result = zupt::sha256(data.data(), data.size());
        return vectorToJByteArray(env, result);
    } catch (const std::exception& e) {
        throwJavaException(env, e);
        return nullptr;
    }
}

JNIEXPORT jbyteArray JNICALL Java_com_libzupt_NativeLib_sha3512(JNIEnv* env, jobject /* self */, jbyteArray jdata) {
    try {
        std::vector<uint8_t> data = jbyteArrayToVector(env, jdata);
        std::vector<uint8_t> result = zupt::sha3_512(data.data(), data.size());
        return vectorToJByteArray(env, result);
    } catch (const std::exception& e) {
        throwJavaException(env, e);
        return nullptr;
    }
}