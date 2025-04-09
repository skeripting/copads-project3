using System.Text;

class Program {
    private const byte MSB_BYTE_MASK =  0b10000000;
    public static string ByteToString(byte b) {
        return Convert.ToString(b, 2).PadLeft(8, '0');
    }

    public static byte[] BinaryStringToBytes(string binary) {
        int numBytes = binary.Length / 8;
        byte[] bytes = new byte[numBytes];
        
        for (int i = 0; i < numBytes; i++) {
            string byteString = binary.Substring(i * 8, 8);
            bytes[i] = Convert.ToByte(byteString, 2);
        }

        return bytes;
    }

    // Performs one step of the LFSR function 
    // Returns the new seed and the new bit as a tuple after execution 
    public static (byte[], int) SimulateOneStepLFSR(byte[] seed, int tap) {
        byte leftmostBit = (byte)((seed[0] & MSB_BYTE_MASK) >> 7);

        int numTotalBits = 8 * seed.Length;  // 8 bits times number of bytes

        int bitIndexFromRight = numTotalBits - tap;  
        int byteIndex = bitIndexFromRight / 8;
        int bitOffset = bitIndexFromRight % 8;

        byte tapBit = (byte)((seed[byteIndex] >> (7 - bitOffset)) & 1);

        byte newBit = (byte)(leftmostBit ^ tapBit);

        int carry = newBit;

        for (int i = seed.Length - 1; i >= 0; i--) {
            int nextCarry = (seed[i] & MSB_BYTE_MASK) >> 7; 
            seed[i] <<= 1; 
            seed[i] |= (byte)carry; 
            carry = nextCarry;
        }

        // at this point, the seed is new
        // last step is to make the XORed thingy (new bit) the LSB 

        seed[seed.Length - 1] |= (byte)(newBit >> 7); // set LSB to new bit 

        foreach (byte b in seed) {
            Console.Write(ByteToString(b));
        }

        Console.Write(" " + newBit);

        Console.WriteLine();

        return (seed, newBit); 
}

    public static void RunKeystream(string[] args) {
        if (args.Length != 4) {
            Console.WriteLine("Error in the length of your arguments.");
            DisplayHelp();
            return; 
        }

        string seedString = args[1];
        int seedLength = seedString.Length;
        int tap, step; 

        try { 
            tap = Convert.ToInt32(args[2]);
        }
        catch {
            Console.WriteLine("Error in converting the tap to an integer.");
            DisplayHelp();
            return;
        }

        try { 
            step = Convert.ToInt32(args[3]);
        }
        catch {
            Console.WriteLine("Error in converting the tap to an integer.");
            DisplayHelp();
            return;
        }

        if (tap < 1 || tap > seedLength) {
            Console.WriteLine("The tap must be within [1.." + seedLength + "]");
            DisplayHelp();
            return;
        }

        Console.WriteLine(seedString + " - seed");

        byte[] seedBytes = BinaryStringToBytes(seedString);
        string keyStream = "";

        for (int i = 0; i < step; i++) {
            var (newSeed, newBit) = SimulateOneStepLFSR(seedBytes, tap);

            seedBytes = newSeed;
            keyStream += newBit;
        }

        String keyStreamPath = Path.Combine(Directory.GetCurrentDirectory(), "keystream.txt");

        using (StreamWriter outputFile = new StreamWriter(keyStreamPath)) {
            outputFile.Write(keyStream);
        }

        Console.WriteLine("The Keystream: " + keyStream);

        // Save the keystream

    }

    public static void RunEncrypt(string[] args) {
        string plaintext = args[0];

        byte[] plainTextBytes = BinaryStringToBytes(plaintext);

        string keyStream; 
        string keyStreamFile = Path.Combine(Directory.GetCurrentDirectory(), "keystream.txt");

        if (!File.Exists(keyStreamFile)) {
            Console.WriteLine("The file " + keyStreamFile + " doesn't exist. Try to run the runkeystream command before using this command first.");
            DisplayHelp();
        }

        using (StreamReader inputFile = new StreamReader(keyStreamFile)) {
            keyStream = inputFile.ReadLine();
        }

        if (keyStream == null || keyStream.Length == 0) {
            Console.WriteLine("An error occurred and the keystream being read was null. Try to run the runkeystream command before using this command first.");
            DisplayHelp();
            return;
        }

        // The keystream may not have the same number of bytes as the plain text
        // So, we need to prepend 0s. 

        int nBytesInPlainText = plainTextBytes.Length;
        int nBytesInKeystream = (keyStream.Length / 8) + 1;

        if (nBytesInKeystream < nBytesInPlainText) {
            Console.WriteLine("Keystream");
            Console.WriteLine(keyStream);
            Console.WriteLine("Plain Text: " + plaintext);
            Console.WriteLine("Number of bytes in Keystream: ");
            Console.WriteLine(nBytesInKeystream);
            Console.WriteLine("Number of bytes in plain text");
            Console.WriteLine(nBytesInPlainText);
        }

        byte[] keystreamBytes = BinaryStringToBytes(keyStream);

        for (int byteIndex = 0; byteIndex < plainTextBytes.Length; byteIndex++) {
            plainTextBytes[byteIndex] ^= (byte)keystreamBytes[byteIndex];
        }


    }

    public static void RunCipher(string[] args) {
        if (args.Length != 3) {
            Console.WriteLine("Error in the length of your arguments.");
            DisplayHelp();
            return; 
        }

        string seedString = args[1];
        byte[] seedBytes = BinaryStringToBytes(seedString);
        int seedLength = seedString.Length;

        int tap;

        try { 
            tap = Convert.ToInt32(args[2]);
        }
        catch {
            Console.WriteLine("Error in converting the tap to an integer.");
            DisplayHelp();
            return;
        }

        if (tap < 1 || tap > seedLength) {
            Console.WriteLine("The tap must be within [1.." + seedLength + "]");
            DisplayHelp();
            return;
        }
        
        Console.WriteLine(seedString + " - seed");

        SimulateOneStepLFSR(seedBytes, tap);
    }

    public static void DisplayHelp() {
        Console.WriteLine(" == Commands: == ");
        Console.WriteLine(" [+] dotnet run cipher <seed> <tap> - Takes an initial seed and tap position and simulates one step of the LFSR cipher.");
        Console.WriteLine(" [+] dotnet run generatekeystream <seed> <tap> <step> - This option will accept a seed, tap position, and the number of steps, n, which is a positive integer. For each step, the LFSR cipher simulation prints the new seed and the rightmost bit.");
        Console.WriteLine(" [+] dotnet run encrypt <plaintext> - This option will accept plaintext in bits; perform an XOR operation of the plaintext with the saved “keystream”; and return a set of encrypted bits (ciphertext).");
        Console.WriteLine(" [+] dotnet run decrypt <ciphertext> - This option will accept ciphertext in bits; perform an XOR operation with the retrieved keystream from the file; and return a set of decrypted bits (plaintext)");
        Console.WriteLine(" [+] dotnet run triplebit <seed> <tap> <step> <iteration> - This option will accept an initial seed, tap, step - a positive integer p and perform p steps of the LFSR cipher simulation. It will also accept iteration- a positive integer w. After each iteration i (0 <= i < w), it returns a new seed, and accumulated integer value.");
        Console.WriteLine(" [+] dotnet run encryptimage <imagefile> <seed> <tap> - Given an image with a seed and tap position, this command will generate a row encrypted version of that image.");
        Console.WriteLine(" [+] dotnet run decryptimage <imagefile> <seed> <tap> - Given an encrypted image, a seed and tap position, this command will generate the original image and save it with a different name in the same directory. The image will be named File_NameNEW.");
    }

    public static void Main(string[] args) {
        if (args.Length == 0) {
            Console.WriteLine("Invalid number of arguments!");
            DisplayHelp();
            return; 
        }

        string option = args[0];

        if (option == "cipher") {
            RunCipher(args);
        }
        else if (option == "generatekeystream") {
            RunKeystream(args);
        }
    }
}