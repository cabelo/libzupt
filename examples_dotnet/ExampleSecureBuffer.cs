using LibZupt;
using System.Text;

namespace ZuptExample;

internal static class ExampleSecureBuffer
{
    public static void Run()
    {
        Console.WriteLine(new string('=', 60));
        Console.WriteLine("libzupt - SecureBuffer Example");
        Console.WriteLine(new string('=', 60));
        Console.WriteLine();

        Console.WriteLine("1. Creating SecureBuffer from bytes...");
        byte[] secret = Encoding.UTF8.GetBytes("My secret password123");
        using (var buffer = new SecureBuffer(secret))
        {
            Console.WriteLine($"   Buffer size: {buffer.Size} bytes");
            Console.WriteLine($"   Buffer content: {buffer.ToUtf8String()}");
            Console.WriteLine();

            Console.WriteLine("2. Creating empty SecureBuffer...");
            using var emptyBuffer = new SecureBuffer(64);
            Console.WriteLine($"   Empty buffer size: {emptyBuffer.Size} bytes");
            Console.WriteLine();

            Console.WriteLine("3. Encrypting with SecureBuffer...");
            var keygen = new KeyGenerator();
            var keypair = keygen.GenerateKeyPair();
            var encryptor = new Encryptor(keypair.PublicKey);
            var decryptor = new Decryptor(keypair.SecretKey);

            var (ciphertext, encHeader) = encryptor.EncryptMemory(buffer);
            Console.WriteLine($"   Ciphertext size: {ciphertext.Length} bytes");
            Console.WriteLine();

            Console.WriteLine("4. Decrypting to SecureBuffer...");
            using var decryptedBuffer = decryptor.DecryptMemorySecure(ciphertext, encHeader);
            Console.WriteLine($"   Decrypted buffer size: {decryptedBuffer.Size} bytes");
            Console.WriteLine($"   Decrypted content: {decryptedBuffer.ToUtf8String()}");
            Console.WriteLine();

            if (!decryptedBuffer.ToBytes().SequenceEqual(secret))
                throw new ZuptException("Decryption failed!");
            Console.WriteLine("5. Verification: SUCCESS");
            Console.WriteLine();

            Console.WriteLine("6. Securely wiping buffer...");
            buffer.Zeroize();
            Console.WriteLine("   Buffer zeroized (content is now zero)");
            Console.WriteLine();
        }

        Console.WriteLine(new string('=', 60));
        Console.WriteLine("SecureBuffer example passed!");
        Console.WriteLine(new string('=', 60));
        Console.WriteLine();
    }
}