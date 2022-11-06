namespace UEFIReader
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello, World!");
            UEFI uefi = new(File.ReadAllBytes(@"C:\Users\Gus\Downloads\xbl_a_PhysicalPart_1_31_05_2022_21_40_53.bin"));
            Console.WriteLine(uefi.EFIs.Count);
        }
    }
}