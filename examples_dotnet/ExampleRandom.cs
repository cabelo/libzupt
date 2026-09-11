using LibZupt;
using System.Text;

namespace ZuptExample;

internal static class ExampleRandom
{
    private static string Hex(byte[] data) => Convert.ToHexString(data).ToLowerInvariant();

    public static void Run()
    {
        Console.WriteLine(new string('=', 60));
        Console.WriteLine("libzupt - Random Bytes and Hashing Example");
        Console.WriteLine(new string('=', 60));
        Console.WriteLine();

        Console.WriteLine("1. Generating random bytes...");
        byte[] randomBytes = Zupt.RandomBytes(32);
        Console.WriteLine($"   Generated {randomBytes.Length} random bytes:");
        Console.WriteLine($"   {Hex(randomBytes)}");
        Console.WriteLine();

        Console.WriteLine("2. Generating AES nonce...");
        byte[] nonce = Zupt.RandomBytes(ZuptConstants.AesNonceSize);
        Console.WriteLine($"   Nonce ({nonce.Length} bytes): {Hex(nonce)}");
        Console.WriteLine();

        Console.WriteLine("3. Computing SHA-256 hash...");
        byte[] data = Encoding.UTF8.GetBytes("Hello, Post-Quantum World!");
        byte[] sha256Hash = Zupt.Sha256(data);
        Console.WriteLine($"   Data: {Encoding.UTF8.GetString(data)}");
        Console.WriteLine($"   SHA-256: {Hex(sha256Hash)}");
        Console.WriteLine();

        Console.WriteLine("4. Computing SHA3-512 hash...");
        byte[] sha3_512Hash = Zupt.Sha3_512(data);
        Console.WriteLine($"   Data: {Encoding.UTF8.GetString(data)}");
        Console.WriteLine($"   SHA3-512: {Hex(sha3_512Hash)}");
        Console.WriteLine();

        Console.WriteLine("5. Simulating key derivation...");
        byte[] salt = Zupt.RandomBytes(16);
        Console.WriteLine($"   Salt: {Hex(salt)}");
        byte[] derivedKey = Zupt.Sha256(Concat(salt, Encoding.UTF8.GetBytes("my-secret-password")));
        Console.WriteLine($"   Derived key (32 bytes): {Hex(derivedKey)}");
        Console.WriteLine();

        Console.WriteLine(new string('=', 60));
        Console.WriteLine("Random bytes and hashing example passed!");
        Console.WriteLine(new string('=', 60));
        Console.WriteLine();
    }

    private static byte[] Concat(byte[] a, byte[] b)
    {
        var result = new byte[a.Length + b.Length];
        a.CopyTo(result, 0);
        b.CopyTo(result, a.Length);
        return result;
    }
}