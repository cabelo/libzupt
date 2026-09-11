using LibZupt;

namespace ZuptExample;

internal static class ExampleKeygen
{
    private static string MakeTempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "zupt_keygen_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    public static void Run()
    {
        Console.WriteLine(new string('=', 60));
        Console.WriteLine("libzupt - Key Generation and Management Example");
        Console.WriteLine(new string('=', 60));
        Console.WriteLine();

        var tmpDir = MakeTempDir();
        try
        {
            var privKeyFile = Path.Combine(tmpDir, "private.key");
            var pubKeyFile = Path.Combine(tmpDir, "public.key");

            Console.WriteLine("1. Generating key pair...");
            var keygen = new KeyGenerator();
            var keypair = keygen.GenerateKeyPair();
            Console.WriteLine($"   Public key: {keypair.PublicKey.Length} bytes");
            Console.WriteLine($"   Private key: {keypair.SecretKey.Length} bytes");
            Console.WriteLine();

            Console.WriteLine("2. Saving key pair...");
            keygen.SaveKeyPair(keypair, privKeyFile);
            Console.WriteLine($"   Saved to: {privKeyFile}");
            Console.WriteLine();

            Console.WriteLine("3. Exporting public key...");
            keygen.ExportPublicKey(privKeyFile, pubKeyFile);
            Console.WriteLine($"   Saved to: {pubKeyFile}");
            Console.WriteLine();

            Console.WriteLine("4. Loading key pair...");
            var loadedKeypair = keygen.LoadKeyPair(privKeyFile);
            Console.WriteLine($"   Loaded public key: {loadedKeypair.PublicKey.Length} bytes");
            Console.WriteLine($"   Loaded private key: {loadedKeypair.SecretKey.Length} bytes");
            if (!loadedKeypair.PublicKey.SequenceEqual(keypair.PublicKey))
                throw new ZuptException("Public keys do not match!");
            if (!loadedKeypair.SecretKey.SequenceEqual(keypair.SecretKey))
                throw new ZuptException("Private keys do not match!");
            Console.WriteLine("   Keys match!");
            Console.WriteLine();

            Console.WriteLine("5. Loading public key only...");
            byte[] loadedPub = keygen.LoadPublicKey(pubKeyFile);
            Console.WriteLine($"   Loaded public key: {loadedPub.Length} bytes");
            if (!loadedPub.SequenceEqual(keypair.PublicKey))
                throw new ZuptException("Public key does not match!");
            Console.WriteLine("   Public key matches!");
            Console.WriteLine();

            Console.WriteLine("6. Key sizes (bytes):");
            Console.WriteLine($"   ML-KEM public key: {ZuptConstants.MlkEmPublicKeyBytes}");
            Console.WriteLine($"   X25519 public key: {ZuptConstants.X25519KeyBytes}");
            Console.WriteLine($"   Hybrid public key: {ZuptConstants.HybridPubKeySize}");
            Console.WriteLine($"   Hybrid private key: {ZuptConstants.HybridPrivKeySize}");
            Console.WriteLine($"   Encryption header: {ZuptConstants.HybridEncHeaderSize}");
            Console.WriteLine();
        }
        finally
        {
            if (Directory.Exists(tmpDir))
                Directory.Delete(tmpDir, recursive: true);
        }

        Console.WriteLine(new string('=', 60));
        Console.WriteLine("Key management example passed!");
        Console.WriteLine(new string('=', 60));
        Console.WriteLine();
    }
}