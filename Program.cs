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

    public static void SimulateOneStepLFSR(byte[] seed, int tap) {
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

        Console.WriteLine();
}

    public static void RunCipher(string[] args) {
        int seedInt = Convert.ToInt32(args[1], 2);
        string seedString = args[1];
        byte[] seedBytes = BinaryStringToBytes(seedString);
        int seedLength = seedString.Length;

        int tap = 0; 

        if (args.Length != 3) {
            Console.WriteLine("Error in the length of your arguments.");
            return; 
        }

        try { 
            tap = Convert.ToInt32(args[2]);
        }
        catch {
            Console.WriteLine("Error in converting the tap to an integer.");
            return;
        }

        if (tap < 1 || tap > seedLength) {
            Console.WriteLine("The tap must be within [1.." + seedLength + "]");
        }
        
        Console.WriteLine(seedString + " - seed");

        SimulateOneStepLFSR(seedBytes, tap);

    }

    public static void Main(string[] args) {
        string option = args[0];

        if (option == "cipher") {
            RunCipher(args);
        }

    }
}