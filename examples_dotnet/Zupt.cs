using System.Runtime.InteropServices;
using System.Text;

namespace LibZupt;

/// <summary>Constants for the hybrid post-quantum encryption scheme (ML-KEM-768 + X25519).</summary>
public static class ZuptConstants
{
    public const int MlkEmPublicKeyBytes = 1184;
    public const int MlkEmSecretKeyBytes = 2400;
    public const int MlkEmCiphertextBytes = 1088;
    public const int MlkEmSsBytes = 32;

    public const int X25519KeyBytes = 32;

    public const int HybridPubKeySize = 1224;       // 8 (header) + 1184 + 32
    public const int HybridPrivKeySize = 3656;      // 8 + 1184 + 32 + 2400 + 32
    public const int HybridEncHeaderSize = 1137;    // 1 + 1088 + 32 + 16

    public const int AesKeySize = 32;
    public const int AesNonceSize = 16;
    public const int HmacSize = 32;

    public const string Version = "2.1.5";
    public const string LibraryName = "libzupt";
}

/// <summary>P/Invoke declarations for the libzupt C API (zupt_cxx.h).</summary>
internal static unsafe class ZuptNative
{
    [DllImport("libzupt", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int zupt_hybrid_keygen_c(byte* pubKey, byte* privKey);

    [DllImport("libzupt", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int zupt_hybrid_export_pubkey_c(byte* privKey, byte* pubKey);

    [DllImport("libzupt", CallingConvention = CallingConvention.Cdecl)]
    internal static extern byte* zupt_hybrid_encrypt(
        byte* pubKey, nuint pubKeyLen,
        byte* plaintext, nuint plaintextLen,
        byte* encHeader, nuint* encHeaderLen, nuint* ciphertextLen);

    [DllImport("libzupt", CallingConvention = CallingConvention.Cdecl)]
    internal static extern byte* zupt_hybrid_decrypt(
        byte* privKey, nuint privKeyLen,
        byte* ciphertext, nuint ciphertextLen,
        byte* encHeader, nuint encHeaderLen, nuint* plaintextLen);

    [DllImport("libzupt", CallingConvention = CallingConvention.Cdecl)]
    internal static extern byte* zupt_read_file(byte* path, nuint* size);

    [DllImport("libzupt", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int zupt_write_file(byte* path, byte* data, nuint size);

    [DllImport("libzupt", CallingConvention = CallingConvention.Cdecl)]
    internal static extern void zupt_random_bytes(byte* buf, nuint len);

    [DllImport("libzupt", CallingConvention = CallingConvention.Cdecl)]
    internal static extern void zupt_sha256(byte* data, nuint len, byte* hash);

    [DllImport("libzupt", CallingConvention = CallingConvention.Cdecl)]
    internal static extern void zupt_sha3_512(byte* data, nuint len, byte* hash);

    [DllImport("libc", EntryPoint = "free", CallingConvention = CallingConvention.Cdecl)]
    internal static extern void free(byte* ptr);

    static ZuptNative()
    {
        NativeLibrary.SetDllImportResolver(typeof(ZuptNative).Assembly, (name, _, _) =>
        {
            if (string.Equals(name, "libc", StringComparison.Ordinal))
            {
                foreach (var candidate in new[] { "libc.so.6", "libc.so", "libSystem.B.dylib" })
                {
                    if (NativeLibrary.TryLoad(candidate, out var handle))
                        return handle;
                }
            }
            return IntPtr.Zero;
        });
    }
}

/// <summary>Error thrown by any libzupt operation that fails.</summary>
public sealed class ZuptException : Exception
{
    public ZuptException(string message) : base(message) { }
    public ZuptException(string code, string message) : base(message) { Code = code; }

    public string? Code { get; }
}

/// <summary>Hybrid post-quantum key pair (public + secret).</summary>
public sealed class KeyPair
{
    public KeyPair(byte[] publicKey, byte[] secretKey)
    {
        PublicKey = publicKey;
        SecretKey = secretKey;
    }

    public byte[] PublicKey { get; }
    public byte[] SecretKey { get; }
}

/// <summary>Sensitive buffer zeroized on dispose.</summary>
public sealed class SecureBuffer : IDisposable
{
    private byte[] _data;

    public SecureBuffer(byte[] data)
    {
        _data = (byte[])data.Clone();
    }

    public SecureBuffer(int size)
    {
        _data = new byte[size];
    }

    public int Size => _data.Length;
    public int Length => _data.Length;

    public byte[] ToBytes() => _data;

    public string ToUtf8String() => Encoding.UTF8.GetString(_data);

    public override string ToString() => ToUtf8String();

    public void Zeroize()
    {
        Array.Clear(_data, 0, _data.Length);
    }

    public void Dispose()
    {
        Zeroize();
    }
}

/// <summary>Generates and manages hybrid post-quantum key pairs.</summary>
public sealed class KeyGenerator
{
    public KeyPair GenerateKeyPair()
    {
        var pub = new byte[ZuptConstants.HybridPubKeySize];
        var priv = new byte[ZuptConstants.HybridPrivKeySize];

        unsafe
        {
            fixed (byte* pPub = pub)
            fixed (byte* pPriv = priv)
            {
                if (ZuptNative.zupt_hybrid_keygen_c(pPub, pPriv) != 0)
                    throw new ZuptException("Failed to generate key pair");
            }
        }

        return new KeyPair(pub, priv);
    }

    public static byte[] ExportPublicKey(byte[] privKey)
    {
        var pub = new byte[ZuptConstants.HybridPubKeySize];

        unsafe
        {
            fixed (byte* pPriv = privKey)
            fixed (byte* pPub = pub)
            {
                if (ZuptNative.zupt_hybrid_export_pubkey_c(pPriv, pPub) != 0)
                    throw new ZuptException("Failed to export public key");
            }
        }

        return pub;
    }

    public void SaveKeyPair(KeyPair keyPair, string filename)
    {
        Zupt.WriteFile(filename, keyPair.SecretKey);
    }

    public KeyPair LoadKeyPair(string filename)
    {
        var data = Zupt.ReadFile(filename);
        if (data.Length < ZuptConstants.HybridPrivKeySize)
            throw new ZuptException("Key file too small for a private key");

        return new KeyPair(ExportPublicKey(data), data);
    }

    public byte[] LoadPublicKey(string filename)
    {
        var data = Zupt.ReadFile(filename);
        if (data.Length < ZuptConstants.HybridPubKeySize)
            throw new ZuptException("Key file too small for a public key");

        return data.AsSpan(0, ZuptConstants.HybridPubKeySize).ToArray();
    }

    public void ExportPublicKey(string privFile, string pubFile)
    {
        var priv = Zupt.ReadFile(privFile);
        if (priv.Length < ZuptConstants.HybridPrivKeySize)
            throw new ZuptException("Private key file too small");

        Zupt.WriteFile(pubFile, ExportPublicKey(priv));
    }
}

/// <summary>Encrypts data/files using hybrid post-quantum encryption.</summary>
public sealed class Encryptor
{
    private readonly byte[] _publicKey;

    public Encryptor(byte[] publicKey)
    {
        _publicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
    }

    public static int HeaderSize => ZuptConstants.HybridEncHeaderSize;

    public (byte[] Ciphertext, byte[] EncryptionHeader) EncryptMemory(byte[] plaintext)
        => Encrypt(plaintext);

    public (byte[] Ciphertext, byte[] EncryptionHeader) EncryptMemory(SecureBuffer buffer)
        => Encrypt(buffer.ToBytes());

    public (byte[] Ciphertext, byte[] EncryptionHeader) EncryptFile(string filename)
    {
        var data = Zupt.ReadFile(filename);
        return Encrypt(data);
    }

    public unsafe (byte[] Ciphertext, byte[] EncryptionHeader) Encrypt(byte[] plaintext)
    {
        if (plaintext is null)
            throw new ArgumentNullException(nameof(plaintext));

        var encHeader = new byte[ZuptConstants.HybridEncHeaderSize];
        byte* ciphertext = null;

        try
        {
            fixed (byte* pPub = _publicKey)
            fixed (byte* pPlain = plaintext)
            fixed (byte* pHdr = encHeader)
            {
                nuint hdrLen = (nuint)encHeader.Length;
                nuint ctLen = 0;

                ciphertext = ZuptNative.zupt_hybrid_encrypt(
                    pPub, (nuint)_publicKey.Length,
                    pPlain, (nuint)plaintext.Length,
                    pHdr, &hdrLen, &ctLen);

                if (ciphertext == null)
                    throw new ZuptException("Encryption failed");

                var ct = new byte[checked((int)ctLen)];
                Marshal.Copy((IntPtr)ciphertext, ct, 0, ct.Length);

                var hdr = new byte[checked((int)hdrLen)];
                Array.Copy(encHeader, hdr, hdr.Length);

                return (ct, hdr);
            }
        }
        finally
        {
            if (ciphertext != null)
                ZuptNative.free(ciphertext);
        }
    }
}

/// <summary>Decrypts data/files using hybrid post-quantum encryption.</summary>
public sealed class Decryptor
{
    private readonly byte[] _privateKey;

    public Decryptor(byte[] privateKey)
    {
        _privateKey = privateKey ?? throw new ArgumentNullException(nameof(privateKey));
    }

    public byte[] DecryptMemory(byte[] ciphertext, byte[] encHeader)
        => Decrypt(ciphertext, encHeader);

    public byte[] DecryptFile(string filename, byte[] encHeader)
    {
        var ciphertext = Zupt.ReadFile(filename);
        return Decrypt(ciphertext, encHeader);
    }

    public SecureBuffer DecryptMemorySecure(byte[] ciphertext, byte[] encHeader)
    {
        var plaintext = Decrypt(ciphertext, encHeader);
        return new SecureBuffer(plaintext);
    }

    public unsafe byte[] Decrypt(byte[] ciphertext, byte[] encHeader)
    {
        if (ciphertext is null)
            throw new ArgumentNullException(nameof(ciphertext));
        if (encHeader is null)
            throw new ArgumentNullException(nameof(encHeader));

        byte* plaintext = null;

        try
        {
            fixed (byte* pPriv = _privateKey)
            fixed (byte* pCt = ciphertext)
            fixed (byte* pHdr = encHeader)
            {
                nuint ptLen = 0;

                plaintext = ZuptNative.zupt_hybrid_decrypt(
                    pPriv, (nuint)_privateKey.Length,
                    pCt, (nuint)ciphertext.Length,
                    pHdr, (nuint)encHeader.Length,
                    &ptLen);

                if (plaintext == null)
                    throw new ZuptException("Decryption failed (wrong key or corrupted data)");

                var pt = new byte[checked((int)ptLen)];
                Marshal.Copy((IntPtr)plaintext, pt, 0, pt.Length);
                return pt;
            }
        }
        finally
        {
            if (plaintext != null)
                ZuptNative.free(plaintext);
        }
    }
}

/// <summary>Helper functions exposed by the libzupt C API.</summary>
public static class Zupt
{
    public static byte[] RandomBytes(int size)
    {
        var buf = new byte[size];

        unsafe
        {
            fixed (byte* p = buf)
                ZuptNative.zupt_random_bytes(p, (nuint)size);
        }

        return buf;
    }

    public static byte[] Sha256(byte[] data)
    {
        var hash = new byte[32];

        unsafe
        {
            fixed (byte* pData = data)
            fixed (byte* pHash = hash)
                ZuptNative.zupt_sha256(pData, (nuint)data.Length, pHash);
        }

        return hash;
    }

    public static byte[] Sha256(byte[] data, int offset, int count)
    {
        var slice = data.AsSpan(offset, count).ToArray();
        return Sha256(slice);
    }

    public static byte[] Sha3_512(byte[] data)
    {
        var hash = new byte[64];

        unsafe
        {
            fixed (byte* pData = data)
            fixed (byte* pHash = hash)
                ZuptNative.zupt_sha3_512(pData, (nuint)data.Length, pHash);
        }

        return hash;
    }

    public static void SecureWipe(byte[] data)
    {
        if (data is not null)
            Array.Clear(data, 0, data.Length);
    }

    public static unsafe byte[] ReadFile(string path)
    {
        var cPath = Encoding.UTF8.GetBytes(path + "\0");
        byte* data = null;
        nuint size = 0;

        try
        {
            fixed (byte* pPath = cPath)
            {
                data = ZuptNative.zupt_read_file(pPath, &size);
            }

            if (data == null)
                throw new ZuptException("Failed to read file: " + path);

            var buf = new byte[checked((int)size)];
            Marshal.Copy((IntPtr)data, buf, 0, buf.Length);
            return buf;
        }
        finally
        {
            if (data != null)
                ZuptNative.free(data);
        }
    }

    public static void WriteFile(string path, byte[] data)
    {
        var cPath = Encoding.UTF8.GetBytes(path + "\0");

        unsafe
        {
            fixed (byte* pPath = cPath)
            fixed (byte* pData = data)
            {
                if (ZuptNative.zupt_write_file(pPath, pData, (nuint)data.Length) != 0)
                    throw new ZuptException("Failed to write file: " + path);
            }
        }
    }

    public static string GetVersion() => ZuptConstants.Version;

    public static string GetLibraryName() => ZuptConstants.LibraryName;
}