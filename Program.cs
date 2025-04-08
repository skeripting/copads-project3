class Program {
    public static void RunCipher(string[] args) {
        string seed = args[1];
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
    

    }

    public static void main(string[] args) {
        string option = args[0];

        if (option == "cipher") {
            RunCipher(args);
        }

    }
}