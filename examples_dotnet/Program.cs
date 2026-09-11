using LibZupt;
using ZuptExample;

var examples = new (string Name, string Title, Action Run)[]
{
    ("basic", "Basic Encryption/Decryption", ExampleBasic.Run),
    ("file", "File Encryption/Decryption", ExampleFile.Run),
    ("keygen", "Key Generation and Management", ExampleKeygen.Run),
    ("random", "Random Bytes and Hashing", ExampleRandom.Run),
    ("secure_buffer", "SecureBuffer", ExampleSecureBuffer.Run),
};

try
{
    string selection = args.Length == 0 ? "all" : args[0].ToLowerInvariant();

    if (selection == "all" || selection == "--all")
    {
        foreach (var ex in examples)
            ex.Run();
    }
    else if (selection is "-h" or "--help" or "help")
    {
        Console.WriteLine("Usage: zupt_example [example]");
        Console.WriteLine();
        Console.WriteLine("Available examples:");
        foreach (var ex in examples)
            Console.WriteLine($"  {ex.Name,-14} {ex.Title}");
        Console.WriteLine("  all            Run every example (default)");
        return 0;
    }
    else
    {
        var example = examples.FirstOrDefault(e => e.Name == selection);
        if (example.Name is null)
            throw new ArgumentException($"Unknown example: '{selection}'");
        example.Run();
    }

    return 0;
}
catch (Exception ex)
{
    Console.Error.WriteLine();
    Console.Error.WriteLine($"ERROR: {ex.Message}");
    return 1;
}