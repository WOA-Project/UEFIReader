namespace UEFIReader
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            ExtractQualcommUEFIImage(@"F:\TestUEFIReader\Arcata.img", @"F:\TestUEFIReader\Arcata");
            ExtractQualcommUEFIImage(@"F:\TestUEFIReader\BlackRock.img", @"F:\TestUEFIReader\BlackRock");
            ExtractQualcommUEFIImage(@"F:\TestUEFIReader\Cambria.img", @"F:\TestUEFIReader\Cambria");
            ExtractQualcommUEFIImage(@"F:\TestUEFIReader\Carina.img", @"F:\TestUEFIReader\Carina");
            ExtractQualcommUEFIImage(@"F:\TestUEFIReader\Epsilon.img", @"F:\TestUEFIReader\Epsilon");
            ExtractQualcommUEFIImage(@"F:\TestUEFIReader\Zeta.img", @"F:\TestUEFIReader\Zeta");
            ExtractQualcommUEFIImage(@"F:\TestUEFIReader\Caspar.img", @"F:\TestUEFIReader\Caspar");
            ExtractQualcommUEFIImage(@"F:\TestUEFIReader\Sydney.img", @"F:\TestUEFIReader\Sydney");
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