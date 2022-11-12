namespace UEFIReader
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            if (args.Length == 2 && File.Exists(args[0]))
            {
                ExtractQualcommUEFIImage(args[0], args[1]);
            }
            else
            {
                Console.WriteLine("Usage: <Path to UEFI image/XBL image> <Output Directory>");
            }
        }

        private static void ExtractQualcommUEFIImage(string UEFIPath, string Output)
        {
            UEFI uefi = new(File.ReadAllBytes(UEFIPath));
            if (!string.IsNullOrEmpty(uefi.BuildId))
            {
                Output = Path.Combine(Output, uefi.BuildId);
            }

            uefi.ExtractUEFI(Output);
        }
    }
}