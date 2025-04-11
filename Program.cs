using System.Text;
using SkiaSharp;

// Program class. Handles the entire project 3.
class Program {
    // This is basically a mask where the first bit is 1
    private const byte MSB_BYTE_MASK =  0b10000000;

    // Convert a byte into a string
    public static string ByteToString(byte b) {
        return Convert.ToString(b, 2).PadLeft(8, '0');
    }

    // Convert multiple bytes to string
    public static string BytesToBinaryString(byte[] bytes)
    {
        StringBuilder binaryString = new StringBuilder();

        foreach (byte b in bytes)
        {
            binaryString.Append(ByteToString(b));
        }

        return binaryString.ToString();
    }

    // Convert a string into bytes
    public static byte[] BinaryStringToBytes(string binary)
    {
        int remainder = binary.Length % 8;
        if (remainder != 0)
        {
            binary = binary.PadLeft(binary.Length + (8 - remainder), '0');
        }

        int numBytes = binary.Length / 8;
        byte[] bytes = new byte[numBytes];

        for (int i = 0; i < numBytes; i++)
        {
            string byteString = binary.Substring(i * 8, 8);
            bytes[i] = Convert.ToByte(byteString, 2);
        }

        return bytes;
    }

    // Performs one step of the LFSR function 
    // Returns the new seed and the new bit as a tuple after execution 
    public static (byte[], byte) SimulateOneStepLFSR(byte[] seed, int tap, bool shouldWrite = true) {
        
        byte leftmostBit = (byte)((seed[0] & MSB_BYTE_MASK) >> 7);

        int numTotalBits = 8 * seed.Length;  // 8 bits times number of bytes

        // ChatGPT wrote everything below this line

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

        // ChatGPT wrote all the way to this line. Everything else is my code.
        
        // at this point, the seed is new
        // last step is to make the XORed thingy (new bit) the LSB 

        seed[seed.Length - 1] |= (byte)(newBit >> 7); // set LSB to new bit 

        if (shouldWrite) {
            foreach (byte b in seed) {
                Console.Write(ByteToString(b));
            }

            Console.Write(" " + newBit);

            Console.WriteLine();
        }
        
        return (seed, newBit); 
    }

    // Encrypts an image
    public static void RunEncryptImage(string[] args) {
        if (args.Length != 4) {
            Console.WriteLine("Error in the length of your arguments.");
            DisplayHelp();
            return; 
        }

        string imageFile; 
        string seed; 
        int tap;

        try {
            imageFile = args[1];
        }
        catch {
            Console.WriteLine("Error in converting the image file into a string");
            DisplayHelp();
            return; 
        }

        try {
            seed = args[2];
        }
        catch {
            Console.WriteLine("Error in converting the seed into a string");
            DisplayHelp();
            return; 
        }

        try {
            tap = Convert.ToInt32(args[3]);
        }
        catch {
            Console.WriteLine("Error in converting the tap into an int");
            DisplayHelp();
            return; 
        }

        byte[] seedBytes = BinaryStringToBytes(seed);

        var (newSeed, _) = SimulateOneStepLFSR(seedBytes, tap, false);

        string imagePath = Path.Combine(Directory.GetCurrentDirectory(), imageFile);
        SKBitmap bitmap;

        using (FileStream fs = new FileStream(imagePath, FileMode.Open)) {
            bitmap = SKBitmap.Decode(fs);
        }

        System.Console.WriteLine("Encrypting image " + imagePath + "...");

        for (int x = 0; x < bitmap.Width; x++) {
            for (int y = 0; y < bitmap.Height; y++) {
                string randomRedIntString = "";
                string randomGreenIntString = "";
                string randomBlueIntString = "";

                for (int i = 0; i < 8; i++) {
                    var (newRedByte, newRedBit) = SimulateOneStepLFSR(newSeed, tap, false);
                    newSeed = newRedByte;
                    randomRedIntString += newRedBit;

                    var (newGreenByte, newGreenBit) = SimulateOneStepLFSR(newSeed, tap, false);
                    newSeed = newGreenByte;
                    randomGreenIntString += newGreenBit;

                    var (newBlueByte, newBlueBit) = SimulateOneStepLFSR(newSeed, tap, false);
                    newSeed = newBlueByte;
                    randomBlueIntString += newBlueBit;
                }

                int randomRedInt = Convert.ToInt32(randomRedIntString, 2);
                int randomGreenInt = Convert.ToInt32(randomGreenIntString, 2);
                int randomBlueInt = Convert.ToInt32(randomBlueIntString, 2);

                SKColor pixelColor = bitmap.GetPixel(x, y);

                byte redColor = pixelColor.Red;
                byte blueColor = pixelColor.Blue;
                byte greenColor = pixelColor.Green;

                byte newRedColor = (byte)(redColor ^ randomRedInt);
                byte newGreenColor = (byte)(greenColor ^ randomGreenInt);
                byte newBlueColor = (byte)(blueColor ^ randomBlueInt);

                SKColor newPixelColor = new SKColor(newRedColor, newGreenColor, newBlueColor);
                bitmap.SetPixel(x, y, newPixelColor);
            }
        }

        string imageFileWithoutExtension = Path.GetFileNameWithoutExtension(imageFile);
        string newImagePath = Path.Combine(Directory.GetCurrentDirectory(), imageFileWithoutExtension + "ENCRYPTED" + Path.GetExtension(imageFile));
        
        SKImage skImage = SKImage.FromBitmap(bitmap);
        SKData encodedData = skImage.Encode(SKEncodedImageFormat.Png, 100);
        using (FileStream outFile = File.OpenWrite(newImagePath)) {
            encodedData.SaveTo(outFile);
        }

        System.Console.WriteLine("Encryption complete.");
    }

    // Decrypts the encrypted image from the previous method
    public static void RunDecryptImage(string[] args) {
        if (args.Length != 4) {
            Console.WriteLine("Error in the length of your arguments.");
            DisplayHelp();
            return; 
        }

        string imageFile; 
        string seed; 
        int tap;

        try {
            imageFile = args[1];
        }
        catch {
            Console.WriteLine("Error in converting the image file into a string");
            DisplayHelp();
            return; 
        }

        try {
            seed = args[2];
        }
        catch {
            Console.WriteLine("Error in converting the seed into a string");
            DisplayHelp();
            return; 
        }

        try {
            tap = Convert.ToInt32(args[3]);
        }
        catch {
            Console.WriteLine("Error in converting the tap into an int");
            DisplayHelp();
            return; 
        }

        byte[] seedBytes = BinaryStringToBytes(seed);

        var (newSeed, _) = SimulateOneStepLFSR(seedBytes, tap, false);

        string imagePath = Path.Combine(Directory.GetCurrentDirectory(), imageFile);
        SKBitmap bitmap;

        using (FileStream fs = new FileStream(imagePath, FileMode.Open)) {
            bitmap = SKBitmap.Decode(fs);
        }

        Console.WriteLine("Decrypting image " + imagePath + "...");

        for (int x = 0; x < bitmap.Width; x++) {
            for (int y = 0; y < bitmap.Height; y++) {
                string randomRedIntString = "";
                string randomGreenIntString = "";
                string randomBlueIntString = "";
                
                for (int i = 0; i < 8; i++) {
                    var (newRedByte, newRedBit) = SimulateOneStepLFSR(newSeed, tap, false);
                    newSeed = newRedByte;
                    randomRedIntString += newRedBit;

                    var (newGreenByte, newGreenBit) = SimulateOneStepLFSR(newSeed, tap, false);
                    newSeed = newGreenByte;
                    randomGreenIntString += newGreenBit;

                    var (newBlueByte, newBlueBit) = SimulateOneStepLFSR(newSeed, tap, false);
                    newSeed = newBlueByte;
                    randomBlueIntString += newBlueBit;
                }

                int randomRedInt = Convert.ToInt32(randomRedIntString, 2);
                int randomGreenInt = Convert.ToInt32(randomGreenIntString, 2);
                int randomBlueInt = Convert.ToInt32(randomBlueIntString, 2);

                SKColor pixelColor = bitmap.GetPixel(x, y);
                byte redColor = pixelColor.Red;
                byte blueColor = pixelColor.Blue;
                byte greenColor = pixelColor.Green;

                byte newRedColor = (byte)(redColor ^ randomRedInt);
                byte newGreenColor = (byte)(greenColor ^ randomGreenInt);
                byte newBlueColor = (byte)(blueColor ^ randomBlueInt);

                SKColor newPixelColor = new SKColor(newRedColor, newGreenColor, newBlueColor);
                bitmap.SetPixel(x, y, newPixelColor);
            }
        }

        string imageFileWithoutExtension = Path.GetFileNameWithoutExtension(imageFile);
        string newImagePath = Path.Combine(Directory.GetCurrentDirectory(), imageFileWithoutExtension.Replace("ENCRYPTED", "") + "NEW" + Path.GetExtension(imageFile));
        
        SKImage skImage = SKImage.FromBitmap(bitmap);
        SKData encodedData = skImage.Encode(SKEncodedImageFormat.Png, 100);
        using (FileStream outFile = File.OpenWrite(newImagePath)) {
            encodedData.SaveTo(outFile);
        }

        System.Console.WriteLine("Decryption complete.");
    }

    // Runs the keystream command
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

        string keyStreamPath = Path.Combine(Directory.GetCurrentDirectory(), "keystream.txt");

        using (StreamWriter outputFile = new StreamWriter(keyStreamPath)) {
            outputFile.Write(keyStream);
        }

        Console.WriteLine("The Keystream: " + keyStream);

    }

    // Runs the encrypt ocmmand
    public static void RunEncrypt(string[] args) {
        string plaintext = args[1];

        string keyStream;
        string keyStreamFile = Path.Combine(Directory.GetCurrentDirectory(), "keystream.txt");

        if (!File.Exists(keyStreamFile)) {
            Console.WriteLine("The file " + keyStreamFile + " doesn't exist. Try running 'generatekeystream'");
            DisplayHelp();
            return;
        }

        using (StreamReader inputFile = new StreamReader(keyStreamFile)) {
            keyStream = inputFile.ReadLine();
        }

        if (keyStream == null || keyStream.Length == 0) {
            Console.WriteLine("Keystream read as null or empty. Try running 'generatekeystream'");
            DisplayHelp();
            return;
        }

        // at this point the arrays may not be the same length 
        // so i padded them

        while (keyStream.Length < plaintext.Length) {
            keyStream = "0" + keyStream;
        }

        while (plaintext.Length < keyStream.Length) {
            plaintext = "0" + plaintext;
        }

        byte[] keystreamBytes = BinaryStringToBytes(keyStream);
        byte[] plainTextBytes = BinaryStringToBytes(plaintext);

        // now finally they should be the same length *rolls eyes*; xor 

        for (int i = 0; i < keystreamBytes.Length; i++) {
            plainTextBytes[i] ^= keystreamBytes[i];
        }

        string newCipherText = "";

        Console.Write("The cipher text is: ");
        for (int i = 0; i < plainTextBytes.Length; i++) {
            newCipherText += ByteToString(plainTextBytes[i]);
        }

        Console.WriteLine(newCipherText);
    }


    // Runs the decrypt command
    public static void RunDecrypt(string[] args) {
        string ciphertext = args[1];

        string keyStream;
        string keyStreamFile = Path.Combine(Directory.GetCurrentDirectory(), "keystream.txt");

        if (!File.Exists(keyStreamFile)) {
            Console.WriteLine("The file " + keyStreamFile + " doesn't exist. Try running 'generatekeystream'");
            DisplayHelp();
            return;
        }

        using (StreamReader inputFile = new StreamReader(keyStreamFile)) {
            keyStream = inputFile.ReadLine();
        }

        if (keyStream == null || keyStream.Length == 0) {
            Console.WriteLine("Keystream read as null or empty. Try running 'generatekeystream'");
            DisplayHelp();
            return;
        }

        // at this point the arrays may not be the same length 
        // so i padded them

        while (keyStream.Length < ciphertext.Length) {
            keyStream = "0" + keyStream;
        }

        while (ciphertext.Length < keyStream.Length) {
            ciphertext = "0" + ciphertext;
        }

        byte[] keystreamBytes = BinaryStringToBytes(keyStream);
        byte[] cipherTextBytes = BinaryStringToBytes(ciphertext);

        // cipher text bytes should be same size as keystream bytes now
        byte[] plainTextBytes = new byte[keystreamBytes.Length]; 

        // now finally they should be the same length *rolls eyes*; xor 


        // plain text = C_i XOR k_i

        for (int i = 0; i < keystreamBytes.Length; i++) {
            plainTextBytes[i] = (byte)(cipherTextBytes[i] ^ keystreamBytes[i]);
        }

        string newPlainText = "";

        Console.Write("The plain text is: ");
        for (int i = 0; i < plainTextBytes.Length; i++) {
            newPlainText += ByteToString(plainTextBytes[i]);
        }

        // at this point, the bytetostring function has added leading zeroes 

        //newPlainText = newPlainText.TrimStart('0');

        // 0s removed (nvm - important notes stuff says dont do that)
        // this will cause the output to not match the expected one but ig
        // thats ok

        Console.WriteLine(newPlainText);
    }

    public static void RunTripleBit(string[] args) {
        if (args.Length != 5) {
            Console.WriteLine("Error in the length of your arguments.");
            DisplayHelp();
            return;
        }

        string seedString = args[1];
        int seedLength = seedString.Length;
        byte[] seedBytes = BinaryStringToBytes(seedString);

        int tap, step, iteration;
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
            Console.WriteLine("Error in converting the step to an integer.");
            DisplayHelp();
            return;
        }
        try {
            iteration = Convert.ToInt32(args[4]);
        }
        catch {
            Console.WriteLine("Error in converting the iteration to an integer.");
            DisplayHelp();
            return;
        }

        if (tap < 1 || tap > seedLength) {
            Console.WriteLine("The tap must be within [1.." + seedLength + "]");
            DisplayHelp();
            return;
        }

        Console.WriteLine(seedString + " - seed");

        for (int i = 0; i < iteration; i++) {
            int accumulated = 1; 
            for (int j = 0; j < step; j++) {
                var (newSeed, newBit) = SimulateOneStepLFSR(seedBytes, tap, false);
                seedBytes = newSeed;
                accumulated = accumulated * 3 + newBit;
            }
            string finalSeedBinary = BytesToBinaryString(seedBytes);
            Console.WriteLine(finalSeedBinary + " " + accumulated);
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
        
        try {
            if (option.ToLower() == "cipher") {
                RunCipher(args);
            }
            else if (option.ToLower() == "generatekeystream") {
                RunKeystream(args);
            }
            else if (option.ToLower() == "encrypt") {
                RunEncrypt(args);
            }
            else if (option.ToLower() == "decrypt") {
                RunDecrypt(args);
            }
            else if (option.ToLower() == "triplebit" || option.ToLower() == "triplebits") {  
                RunTripleBit(args);
            }
            else if (option.ToLower() == "encryptimage") {
                RunEncryptImage(args);
            }
            else if (option.ToLower() == "decryptimage") {
                RunDecryptImage(args);
            }
            else {
                Console.WriteLine("Invalid Command!");
                DisplayHelp();
                return;
            }
        }
        catch {
            Console.WriteLine("An error occurred in the process of running your command.");
            Console.WriteLine("Please double check your arugments and make sure that the order and formatting is correct.");
            DisplayHelp();
        }
    }
}