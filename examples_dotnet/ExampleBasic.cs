using LibZupt;
using System.Text;

namespace ZuptExample;

internal static class ExampleBasic
{
    public static void Run()
    {
        Console.WriteLine(new string('=', 60));
        Console.WriteLine("libzupt - Basic Encryption/Decryption Example");
        Console.WriteLine(new string('=', 60));
        Console.WriteLine();

        Console.WriteLine("1. Generating key pair...");
        var keygen = new KeyGenerator();
        var keypair = keygen.GenerateKeyPair();
        Console.WriteLine($"   Public key size: {keypair.PublicKey.Length} bytes");
        Console.WriteLine($"   Secret key size: {keypair.SecretKey.Length} bytes");
        Console.WriteLine();

        var encryptor = new Encryptor(keypair.PublicKey);
        var decryptor = new Decryptor(keypair.SecretKey);

        byte[] message = Encoding.UTF8.GetBytes("Hello, Post-Quantum World! This is a secret message.");
        Console.WriteLine($"2. Encrypting message: {Encoding.UTF8.GetString(message)}");
        var (ciphertext, encHeader) = encryptor.EncryptMemory(message);
        Console.WriteLine($"   Ciphertext size: {ciphertext.Length} bytes");
        Console.WriteLine($"   Header size: {encHeader.Length} bytes");
        Console.WriteLine();

        Console.WriteLine("3. Decrypting...");
        byte[] decrypted = decryptor.DecryptMemory(ciphertext, encHeader);
        Console.WriteLine($"   Decrypted: {Encoding.UTF8.GetString(decrypted)}");
        Console.WriteLine();

        if (!decrypted.SequenceEqual(message))
            throw new ZuptException("Decryption failed!");
        Console.WriteLine("4. Verification: SUCCESS - Decrypted message matches original");
        Console.WriteLine();

        Console.WriteLine("5. Testing with wrong key...");
        var keygen2 = new KeyGenerator();
        var keypair2 = keygen2.GenerateKeyPair();
        var decryptorWrong = new Decryptor(keypair2.SecretKey);

        try
        {
            decryptorWrong.DecryptMemory(ciphertext, encHeader);
            Console.WriteLine("   ERROR: Should have failed!");
        }
        catch (ZuptException e)
        {
            Console.WriteLine($"   Correctly rejected with error: {e.Message}");
        }
        Console.WriteLine();

        Console.WriteLine(new string('=', 60));
        Console.WriteLine("All examples passed!");
        Console.WriteLine(new string('=', 60));
        Console.WriteLine();
    }
}