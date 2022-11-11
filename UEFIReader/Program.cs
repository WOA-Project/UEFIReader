namespace UEFIReader
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            new UEFI(File.ReadAllBytes(@"F:\TestUEFIReader\Arcata.img")).ExtractUEFI(@"F:\TestUEFIReader\Arcata");
            new UEFI(File.ReadAllBytes(@"F:\TestUEFIReader\BlackRock.img")).ExtractUEFI(@"F:\TestUEFIReader\BlackRock");
            new UEFI(File.ReadAllBytes(@"F:\TestUEFIReader\Cambria.img")).ExtractUEFI(@"F:\TestUEFIReader\Cambria");
            new UEFI(File.ReadAllBytes(@"F:\TestUEFIReader\Carina.img")).ExtractUEFI(@"F:\TestUEFIReader\Carina");
            new UEFI(File.ReadAllBytes(@"F:\TestUEFIReader\Epsilon.img")).ExtractUEFI(@"F:\TestUEFIReader\Epsilon");
            new UEFI(File.ReadAllBytes(@"F:\TestUEFIReader\Zeta.img")).ExtractUEFI(@"F:\TestUEFIReader\Zeta");
            new UEFI(File.ReadAllBytes(@"F:\TestUEFIReader\Caspar.img")).ExtractUEFI(@"F:\TestUEFIReader\Caspar");
            new UEFI(File.ReadAllBytes(@"F:\TestUEFIReader\Sydney.img")).ExtractUEFI(@"F:\TestUEFIReader\Sydney");
        }
    }
}