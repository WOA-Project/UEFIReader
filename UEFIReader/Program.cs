namespace UEFIReader
{
    internal class Program
    {
        static void Main(string[] args)
        {
            UEFI uefi = new(File.ReadAllBytes(@"C:\Users\Gus\Downloads\BMRs\ota_b1-12-customer_gen_2022.815.152\xbl.img"));
            uefi.ExtractUEFI(@"F:\TestUEFIReader");
        }
    }
}