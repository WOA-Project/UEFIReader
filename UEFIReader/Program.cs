namespace UEFIReader
{
    internal class Program
    {
        static void Main(string[] args)
        {
            UEFI uefi = new(File.ReadAllBytes(@"F:\TestUEFIReader\OEMMK.img"));
            uefi.ExtractUEFI(@"F:\TestUEFIReader");
        }
    }
}