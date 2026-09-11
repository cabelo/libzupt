using LibZupt;
using System.Text;

namespace ZuptExample;

internal static class ExampleFile
{
    private static string MakeTempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "zupt_example_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    public static void Run()
    {
        Console.WriteLine(new string('=', 60));
        Console.WriteLine("libzupt - File Encryption/Decryption Example");
        Console.WriteLine(new string('=', 60));
        Console.WriteLine();

        Console.WriteLine("1. Generating key pair...");
        var keygen = new KeyGenerator();
        var keypair = keygen.GenerateKeyPair();
        Console.WriteLine("   Key pair generated");
        Console.WriteLine();

        var encryptor = new Encryptor(keypair.PublicKey);
        var decryptor = new Decryptor(keypair.SecretKey);

        var tmpDir = MakeTempDir();
        try
        {
            var testFile = Path.Combine(tmpDir, "example.txt");
            var content = new StringBuilder();
            content.AppendLine("This is a secret text file.");
            content.AppendLine("Line 2: Contains sensitive information.");
            content.AppendLine("Line 3: End of file.");
            File.WriteAllText(testFile, content.ToString());
            byte[] originalContent = Encoding.UTF8.GetBytes(content.ToString());

            Console.WriteLine($"2. Created test file: {testFile}");
            Console.WriteLine($"   Original content:\n{Encoding.UTF8.GetString(originalContent)}");

            Console.WriteLine("3. Encrypting file...");
            var (ciphertext, encHeader) = encryptor.EncryptFile(testFile);
            Console.WriteLine($"   Ciphertext size: {ciphertext.Length} bytes");
            Console.WriteLine($"   Header size: {encHeader.Length} bytes");
            Console.WriteLine();

            var cipherFile = testFile + ".enc";
            File.WriteAllBytes(cipherFile, ciphertext);
            Console.WriteLine($"4. Saved ciphertext to: {cipherFile}");
            Console.WriteLine();

            Console.WriteLine("5. Decrypting file...");
            byte[] decrypted = decryptor.DecryptFile(cipherFile, encHeader);
            Console.WriteLine($"   Decrypted size: {decrypted.Length} bytes");
            Console.WriteLine($"   Decrypted content:\n{Encoding.UTF8.GetString(decrypted)}");

            if (!decrypted.SequenceEqual(originalContent))
                throw new ZuptException("Decryption failed!");
            Console.WriteLine();

            Console.WriteLine("6. Cleaned up temporary files");
            Console.WriteLine();
        }
        finally
        {
            if (Directory.Exists(tmpDir))
                Directory.Delete(tmpDir, recursive: true);
        }

        Console.WriteLine(new string('=', 60));
        Console.WriteLine("File encryption/decryption example passed!");
        Console.WriteLine(new string('=', 60));
        Console.WriteLine();
    }
}