// Copyright (c) 2018, Rene Lergner - @Heathcliff74xda
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

using SevenZip.Compression.LZMA;
using System.Diagnostics;
using System.Text.RegularExpressions;

namespace UEFIReader
{
    internal class EFI
    {
        internal Guid Guid;
        internal string Type;
        public EFISection[] SectionElements;
    }

    internal class EFISection
    {
        internal string Name;
        internal string Type;
        public byte[] DecompressedImage;
    }

    internal class UEFI
    {
        internal List<EFI> EFIs = new();

        // First 0x28 bytes are Qualcomm partition header
        // Inside the attributes of the VolumeHeader, the Volume-alignment is set to 8 (on Windows Phone UEFI images)
        // The Volume always starts right after the Qualcomm header at position 0x28.
        // So the VolumeHeader-alignment is always complied.

        internal HashSet<Guid> LoadPriority = new HashSet<Guid>();


        internal UEFI(byte[] UefiBinary)
        {
            UInt32? Offset = ByteOperations.FindAscii(UefiBinary, "_FVH");
            UInt32 VolumeHeaderOffset = Offset == null ? throw new BadImageFormatException() : (UInt32)Offset - 0x28;

            EFIs.AddRange(HandleVolumeImage(UefiBinary, VolumeHeaderOffset));
        }

        internal void ExtractUEFI(string Output)
        {
            ExtractDXEs(Output);
            ExtractAPRIORI(Output);
        }

        internal string GetBasePath()
        {
            List<string> filePaths = new List<string>();
            foreach (var element in EFIs)
            {
                foreach (var section in element.SectionElements)
                {
                    if (section.Type != "UI" && section.Type != "DXE_DEPEX" && section.Type != "RAW" && section.Type != "PEI_DEPEX")
                    {
                        filePaths.AddRange(TryGetFilePath(section.DecompressedImage));
                    }
                }
            }

            string basePath = GetCommonFilePath(filePaths.ToArray(), "/RELEASE_");
            return basePath;
        }

        internal void ExtractDXEs(string Output)
        {
            List<string> dxeLoadList = new List<string>();
            List<string> dxeIncludeList = new List<string>();

            string basePath = GetBasePath();

            foreach (var element in EFIs)
            {
                if (element.SectionElements.Any(x => IsSectionWithPath(x)))
                {
                    var sectionsWithPaths = element.SectionElements.Where(x => IsSectionWithPath(x)).ToArray();

                    List<string> filePathsForElement = new();
                    foreach (var section in sectionsWithPaths)
                    {
                        filePathsForElement.AddRange(TryGetFilePath(section.DecompressedImage));
                    }

                    string outputPath = "";
                    string infPath = "";
                    string baseName = "";

                    var uis = element.SectionElements.Where(x => IsSectionWithUI(x)).ToArray();

                    if (filePathsForElement.Count > 0)
                    {
                        string pathPart1 = filePathsForElement[0].Split(basePath)[1].Split("/DEBUG/")[0];

                        outputPath = string.Join("/", pathPart1.Split("/")[..^1]).Replace('/', Path.DirectorySeparatorChar);
                        infPath = pathPart1.Split("/")[^1] + ".inf";

                        baseName = pathPart1.Split("/")[^1];

                        if (uis.Length > 1)
                        {
                            Console.WriteLine("This file has more than one potential ui..");
                        }
                        else if (uis.Length == 1)
                        {
                            baseName = uis[0].Name;
                        }
                    }
                    else
                    {
                        if (uis.Length > 1)
                        {
                            Console.WriteLine("This file has more than one potential ui..");
                        }
                        else if (uis.Length == 1)
                        {
                            baseName = uis[0].Name;
                            outputPath = baseName;
                            infPath = baseName + ".inf";
                        }
                    }

                    string combinedPath = Path.Combine(Output, outputPath);
                    if (!Directory.Exists(combinedPath))
                    {
                        Directory.CreateDirectory(combinedPath);
                    }

                    string moduleType = element.Type.ToUpper();
                    switch (element.Type)
                    {
                        case "APPLICATION":
                            moduleType = "UEFI_APPLICATION";
                            break;
                        case "DRIVER":
                            moduleType = "DXE_DRIVER";
                            break;
                        case "SECURITY_CORE":
                            moduleType = "SEC";
                            break;
                    }

                    string infoutput = $"[Defines]\r\n  INF_VERSION    = 0x00010005\r\n  BASE_NAME      = {baseName}\r\n  FILE_GUID      = {element.Guid.ToString().ToUpper()}\r\n  MODULE_TYPE    = {moduleType}\r\n  VERSION_STRING = 1.0\r\n  ENTRY_POINT    = EfiEntry\r\n\r\n[Binaries.AARCH64]";

                    foreach (var item in element.SectionElements)
                    {
                        if (item.Type == "UI")
                        {
                            continue;
                        }

                        string type = item.Type;
                        string extension = type.ToLower();
                        switch (type)
                        {
                            case "PE32":
                                extension = "efi";
                                break;
                            case "DXE_DEPEX":
                                extension = "depex";
                                break;
                        }

                        // TODO: Handle when there's more than one PE32/RAW/etc
                        string outputFileName = $"{baseName}.{extension}";

                        infoutput += $"\r\n   {type}|{outputFileName}|RELEASE";

                        File.WriteAllBytes(Path.Combine(combinedPath, outputFileName), item.DecompressedImage);
                    }

                    File.WriteAllText(Path.Combine(combinedPath, infPath), infoutput);

                    dxeLoadList.Add($"INF {Path.Combine(outputPath, infPath).Replace("\\", "/")}");
                    dxeIncludeList.Add($"{Path.Combine(outputPath, infPath).Replace("\\", "/")}");
                }
                else if (element.SectionElements.Any(x => IsSectionWithUI(x)))
                {
                    var uis = element.SectionElements.Where(x => IsSectionWithUI(x)).ToArray();

                    if (uis.Length > 1)
                    {
                        Console.WriteLine("This file has more than one potential ui..");
                    }
                    else
                    {
                        string fileName = uis[0].Name;
                        dxeLoadList.Add($"FILE FREEFORM = {element.Guid.ToString().ToUpper()} {{");
                        foreach (var section in element.SectionElements)
                        {
                            var el = string.IsNullOrEmpty(section.Name) ? fileName : section.Name;

                            if (section.Type == "RAW")
                            {
                                string combinedPath = Path.Combine(Output, "RawFiles");
                                if (!Directory.Exists(combinedPath))
                                {
                                    Directory.CreateDirectory(combinedPath);
                                }

                                File.WriteAllBytes(Path.Combine(combinedPath, fileName), section.DecompressedImage);
                                dxeLoadList.Add($"    SECTION {section.Type} = RawFiles/{el}");
                            }
                            else if (section.Type == "UI")
                            {
                                dxeLoadList.Add($"    SECTION {section.Type} = \"{el}\"");
                            }
                        }
                        dxeLoadList.Add("}");
                    }
                }
                else
                {
                    Console.WriteLine("File doesn't contain a section with a path. This is a file?");
                }
            }

            File.WriteAllLines(Path.Combine(Output, "DXE.dsc.inc"), dxeIncludeList);
            File.WriteAllLines(Path.Combine(Output, "DXE.inc"), dxeLoadList);
        }

        internal void ExtractAPRIORI(string Output)
        {
            List<string> aprioriLoadList = new List<string>();

            aprioriLoadList.Add("APRIORI DXE {");

            string basePath = GetBasePath();

            foreach (var element in EFIs)
            {
                if (element.SectionElements.Any(x => IsSectionWithPath(x)))
                {
                    var sectionsWithPaths = element.SectionElements.Where(x => IsSectionWithPath(x)).ToArray();

                    List<string> filePathsForElement = new();
                    foreach (var section in sectionsWithPaths)
                    {
                        filePathsForElement.AddRange(TryGetFilePath(section.DecompressedImage));
                    }

                    string outputPath = "";
                    string infPath = "";
                    string baseName = "";

                    var uis = element.SectionElements.Where(x => IsSectionWithUI(x)).ToArray();

                    if (filePathsForElement.Count > 0)
                    {
                        string pathPart1 = filePathsForElement[0].Split(basePath)[1].Split("/DEBUG/")[0];

                        outputPath = string.Join("/", pathPart1.Split("/")[..^1]).Replace('/', Path.DirectorySeparatorChar);
                        infPath = pathPart1.Split("/")[^1] + ".inf";

                        baseName = pathPart1.Split("/")[^1];

                        if (uis.Length > 1)
                        {
                            Console.WriteLine("This file has more than one potential ui..");
                        }
                        else if (uis.Length == 1)
                        {
                            baseName = uis[0].Name;
                        }
                    }
                    else
                    {
                        if (uis.Length > 1)
                        {
                            Console.WriteLine("This file has more than one potential ui..");
                        }
                        else if (uis.Length == 1)
                        {
                            baseName = uis[0].Name;
                            outputPath = baseName;
                            infPath = baseName + ".inf";
                        }
                    }

                    if (LoadPriority.Contains(element.Guid))
                    {
                        aprioriLoadList.Add($"    INF {Path.Combine(outputPath, infPath).Replace("\\", "/")}");
                    }
                }
            }

            aprioriLoadList.Add("}");

            File.WriteAllLines(Path.Combine(Output, "APRIORI.inc"), aprioriLoadList);
        }

        internal bool IsSectionWithPath(EFISection section)
        {
            return section.Type != "UI" && section.Type != "DXE_DEPEX" && section.Type != "RAW" && section.Type != "PEI_DEPEX";
        }

        internal bool IsSectionWithUI(EFISection section)
        {
            return section.Type == "UI";
        }

        internal string GetCommonFilePath(string[] filePaths, string basePath = "")
        {
            var transformed = filePaths
                .Select(s => !string.IsNullOrEmpty(basePath) ? s.Split(basePath)[1] : s)
                .Select(s => s.ToArray()).ToList();

            var commonPrefix = new string(transformed.First()
                .Take(transformed.Min(s => s.Length))
                .TakeWhile((c, i) => transformed.All(s => s[i] == c))
                .ToArray());

            return commonPrefix;
        }

        internal string[] TryGetFilePath(byte[] Data)
        {
            Regex regex = new Regex("[a-zA-Z/\\\\0-9_\\-\\.]*\\.dll\\b");
            var results = regex.Matches(System.Text.Encoding.ASCII.GetString(Data)).Select(x => x.Value).ToArray();

            if (!results.Any())
            {
                Console.WriteLine("Unexpected: No result matched for binary. Is this illegal?");
            }
            else if (results.Count() > 1)
            {
                Console.WriteLine("Unexpected: More than one dll path matched for binary. Is this illegal?");
            }

            return results.Select(s => s.Replace("\\", "/").Replace("WIN", "LINUX")).ToArray();
        }

        internal EFI[] HandleVolumeImage(byte[] Input, UInt32 Offset)
        {
            string VolumeHeaderMagic = ByteOperations.ReadAsciiString(Input, Offset + 0x28, 0x04);
            if (VolumeHeaderMagic != "_FVH")
            {
                throw new BadImageFormatException();
            }

            if (!VerifyVolumeChecksum(Input, Offset))
            {
                throw new BadImageFormatException();
            }

            UInt32 VolumeSize = ByteOperations.ReadUInt32(Input, Offset + 0x20); // TODO: This is actually a QWORD
            UInt16 VolumeHeaderSize = ByteOperations.ReadUInt16(Input, Offset + 0x30);
            byte PaddingByteValue = (ByteOperations.ReadUInt32(Input, Offset + 0x2C) & 0x00000800) > 0 ? (byte)0xFF : (byte)0x00; // EFI_FVB_ERASE_POLARITY = 0x00000800

            UInt32 FileHeaderOffset = Offset + VolumeHeaderSize;

            return HandleFileLoop(Input, FileHeaderOffset, Offset + VolumeHeaderSize);
        }

        internal EFI[] HandleFileLoop(byte[] Input, UInt32 Offset, UInt32 Base)
        {
            List<EFI> fileElements = new List<EFI>();

            if (!VerifyFileChecksum(Input, Offset))
            {
                return fileElements.ToArray();
                //throw new BadImageFormatException();
            }

            do
            {
                if (Offset + 0x18 > Input.Length)
                {
                    return fileElements.ToArray();
                }

                (byte FileType, uint FileSize, Guid FileGuid) = ReadFileMetadata(Input, Offset);

                if (Offset + FileSize > Input.Length)
                {
                    return fileElements.ToArray();
                }

                switch (FileType)
                {
                    case 0x02: // EFI_FV_FILETYPE_FREEFORM
                        {
                            if (FileGuid == new Guid("FC510EE7-FFDC-11D4-BD41-0080C73C8881"))
                            {
                                Debug.WriteLine("EFI_FV_FILETYPE_DXE_APRIORI");

                                var elements = HandleSectionLoop(Input, Offset + 0x18, Offset + 0x18);

                                if (elements.Count() > 0 && elements[0].Type == "RAW")
                                {
                                    for (uint i = 0; i < elements[0].DecompressedImage.Length; i += 16)
                                    {
                                        Guid dependencyGuid = ByteOperations.ReadGuid(elements[0].DecompressedImage, i);
                                        Debug.WriteLine(dependencyGuid.ToString().ToUpper());
                                        LoadPriority.Add(dependencyGuid);
                                    }
                                }
                            }
                            else
                            {
                                Debug.WriteLine("EFI_FV_FILETYPE_FREEFORM");
                                var elements = HandleSectionLoop(Input, Offset + 0x18, Offset + 0x18);
                                fileElements.Add(new() { Type = "FREEFORM", Guid = FileGuid, SectionElements = elements });
                            }

                            break;
                        }
                    case 0x03: // EFI_FV_FILETYPE_SECURITY_CORE
                        {
                            Debug.WriteLine("EFI_FV_FILETYPE_SECURITY_CORE");
                            var elements = HandleSectionLoop(Input, Offset + 0x18, Offset + 0x18);
                            fileElements.Add(new() { Type = "SECURITY_CORE", Guid = FileGuid, SectionElements = elements });

                            break;
                        }
                    case 0x05: // EFI_FV_FILETYPE_DXE_CORE
                        {
                            Debug.WriteLine("EFI_FV_FILETYPE_DXE_CORE");
                            var elements = HandleSectionLoop(Input, Offset + 0x18, Offset + 0x18);
                            fileElements.Add(new() { Type = "DXE_CORE", Guid = FileGuid, SectionElements = elements });

                            break;
                        }
                    case 0x07: // EFI_FV_FILETYPE_DRIVER
                        {
                            Debug.WriteLine("EFI_FV_FILETYPE_DRIVER");
                            var elements = HandleSectionLoop(Input, Offset + 0x18, Offset + 0x18);
                            fileElements.Add(new() { Type = "DRIVER", Guid = FileGuid, SectionElements = elements });

                            break;
                        }
                    case 0x09: // EFI_FV_FILETYPE_APPLICATION
                        {
                            Debug.WriteLine("EFI_FV_FILETYPE_APPLICATION");
                            var elements = HandleSectionLoop(Input, Offset + 0x18, Offset + 0x18);
                            fileElements.Add(new() { Type = "APPLICATION", Guid = FileGuid, SectionElements = elements });

                            break;
                        }
                    case 0x0B: // EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE
                        {
                            Debug.WriteLine("EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE");
                            var elements = HandleSectionLoop(Input, Offset + 0x18, Offset + 0x18);
                            foreach (var element in elements)
                            {
                                if (element.Type == "FV")
                                {
                                    fileElements.AddRange(HandleVolumeImage(element.DecompressedImage, 0));
                                }
                            }
                            break;
                        }
                    case 0xF0: // EFI_FV_FILETYPE_FFS_PAD
                        {
                            Debug.WriteLine("EFI_FV_FILETYPE_FFS_PAD");
                            break;
                        }
                    case 0x00:
                    case 0xFF:
                        {
                            return fileElements.ToArray();
                        }
                    default:
                        {
                            Debug.WriteLine($"Unsupported file type! 0x{FileType:X2} with size 0x{FileSize:X4} at offset 0x{Offset:X4}");
                            break;
                        }
                }

                Offset += FileSize;

                // FileHeaderOffset in Volume-body must be Align 8
                // In the file-header-attributes the file-alignment relative to the start of the volume is always set to 1,
                // so that alignment can be ignored.
                Offset = ByteOperations.Align(Base, Offset, 8);
            }
            while (Offset < Input.Length);

            return fileElements.ToArray();
        }

        internal byte[] ReadSectionDataBuffer(byte[] Input, UInt32 Offset)
        {
            (uint SectionSize, byte SectionType) = ReadSectionMetadata(Input, Offset);

            var buffer = new byte[SectionSize - 0x04];
            Buffer.BlockCopy(Input, (int)Offset + 0x04, buffer, 0, buffer.Length);

            return buffer;
        }

        internal EFISection[] HandleSectionLoop(byte[] Input, UInt32 Offset, UInt32 Base)
        {
            List<EFISection> fileElements = new List<EFISection>();

            do
            {
                if (Offset + 0x04 > Input.Length)
                {
                    return fileElements.ToArray();
                }

                (uint SectionSize, byte SectionType) = ReadSectionMetadata(Input, Offset);

                if (Offset + SectionSize > Input.Length)
                {
                    return fileElements.ToArray();
                }

                switch (SectionType)
                {
                    case 0x02: // EFI_SECTION_GUID_DEFINED
                        {
                            Debug.WriteLine("EFI_SECTION_GUID_DEFINED");
                            try
                            {
                                fileElements.AddRange(ParseGuidDefinedSection(Input, Offset, Base));
                            }
                            catch { }
                            break;
                        }
                    case 0x10: // EFI_SECTION_PE32
                        {
                            Debug.WriteLine("EFI_SECTION_PE32");
                            fileElements.Add(new() { Type = "PE32", DecompressedImage = ReadSectionDataBuffer(Input, Offset) });
                            break;
                        }
                    case 0x11: // EFI_SECTION_PIC
                        {
                            Debug.WriteLine("EFI_SECTION_PIC");
                            fileElements.Add(new() { Type = "PIC", DecompressedImage = ReadSectionDataBuffer(Input, Offset) });
                            break;
                        }
                    case 0x12: // EFI_SECTION_TE
                        {
                            Debug.WriteLine("EFI_SECTION_TE");
                            fileElements.Add(new() { Type = "TE", DecompressedImage = ReadSectionDataBuffer(Input, Offset) });
                            break;
                        }
                    case 0x13: // EFI_SECTION_DXE_DEPEX
                        {
                            Debug.WriteLine("EFI_SECTION_DXE_DEPEX");
                            fileElements.Add(new() { Type = "DXE_DEPEX", DecompressedImage = ReadSectionDataBuffer(Input, Offset) });
                            break;
                        }
                    case 0x14: // EFI_SECTION_VERSION
                        {
                            Debug.WriteLine("EFI_SECTION_VERSION");
                            break;
                        }
                    case 0x15: // EFI_SECTION_USER_INTERFACE
                        {
                            Debug.WriteLine("EFI_SECTION_USER_INTERFACE");
                            fileElements.Add(new() { Type = "UI", DecompressedImage = ReadSectionDataBuffer(Input, Offset), Name = ByteOperations.ReadUnicodeString(Input, Offset + 0x04, SectionSize - 0x04).TrimEnd(new char[] { (char)0, ' ' }) });
                            break;
                        }
                    case 0x17: // EFI_SECTION_FIRMWARE_VOLUME_IMAGE
                        {
                            Debug.WriteLine("EFI_SECTION_FIRMWARE_VOLUME_IMAGE");
                            fileElements.Add(new() { Type = "FV", DecompressedImage = ReadSectionDataBuffer(Input, Offset) });
                            break;
                        }
                    case 0x19: // EFI_SECTION_RAW
                        {
                            Debug.WriteLine("EFI_SECTION_RAW");
                            fileElements.Add(new() { Type = "RAW", DecompressedImage = ReadSectionDataBuffer(Input, Offset) });
                            break;
                        }
                    case 0x1B: // EFI_SECTION_PEI_DEPEX
                        {
                            Debug.WriteLine("EFI_SECTION_PEI_DEPEX");
                            fileElements.Add(new() { Type = "PEI_DEPEX", DecompressedImage = ReadSectionDataBuffer(Input, Offset) });
                            break;
                        }
                    case 0x00:
                    case 0xFF:
                        {
                            return fileElements.ToArray();
                        }
                    default:
                        {
                            Debug.WriteLine($"Unsupported section type! 0x{SectionType:X2} with size 0x{SectionSize:X4} at offset 0x{Offset:X4}");
                            break;
                        }
                }

                Offset += SectionSize;

                // Offset must be Align 4
                Offset = ByteOperations.Align(Base, Offset, 4);
            }
            while (Offset < Input.Length);

            return fileElements.ToArray();
        }

        internal (uint SectionSize, byte SectionType) ReadSectionMetadata(byte[] Input, UInt32 Offset)
        {
            uint SectionSize = ByteOperations.ReadUInt24(Input, Offset + 0x00);
            byte SectionType = ByteOperations.ReadUInt8(Input, Offset + 0x03);

            return (SectionSize, SectionType);
        }

        internal (byte FileType, uint FileSize, Guid FileGuid) ReadFileMetadata(byte[] Input, UInt32 Offset)
        {
            byte[] FileGuidBytes = new byte[0x10];
            Buffer.BlockCopy(Input, (int)Offset + 0x00, FileGuidBytes, 0, 0x10);
            Guid FileGuid = new Guid(FileGuidBytes);

            byte FileType = ByteOperations.ReadUInt8(Input, Offset + 0x12);
            uint FileSize = ByteOperations.ReadUInt24(Input, Offset + 0x14);

            return (FileType, FileSize, FileGuid);
        }

        internal EFISection[] ParseGuidDefinedSection(byte[] Input, UInt32 Offset, UInt32 Base)
        {
            byte[] DecompressedImage;

            // Decompress subvolume
            (uint SectionSize, byte SectionType) = ReadSectionMetadata(Input, Offset);

            if (SectionType != 0x02) // EFI_SECTION_GUID_DEFINED
            {
                throw new BadImageFormatException();
            }

            byte[] SectionGuidBytes = new byte[0x10];
            Buffer.BlockCopy(Input, (int)Offset + 0x04, SectionGuidBytes, 0, 0x10);
            Guid SectionGuid = new Guid(SectionGuidBytes);
            ushort SectionHeaderSize = ByteOperations.ReadUInt16(Input, Offset + 0x14);

            uint CompressedSubImageOffset = Offset + SectionHeaderSize;
            uint CompressedSubImageSize = SectionSize - SectionHeaderSize;

            // DECOMPRESS HERE
            if (SectionGuid == new Guid("EE4E5898-3914-4259-9D6E-DC7BD79403CF"))
            {
                // LZMA
                DecompressedImage = LZMA.Decompress(Input, CompressedSubImageOffset, CompressedSubImageSize);
            }
            else if (SectionGuid == new Guid("1D301FE9-BE79-4353-91C2-D23BC959AE0C"))
            {
                // GZip
                DecompressedImage = GZip.Decompress(Input, CompressedSubImageOffset, CompressedSubImageSize);
            }
            else
            {
                // UNSUPPORTED
                throw new BadImageFormatException();
            }

            return HandleSectionLoop(DecompressedImage, 0, Base);
        }

        /*internal byte[] GetFile(string Name)
        {
            EFI File = EFIs.Find(f => string.Equals(Name, f.Name, StringComparison.CurrentCultureIgnoreCase) || string.Equals(Name, f.Guid.ToString(), StringComparison.CurrentCultureIgnoreCase));
            if (File == null)
            {
                return null;
            }

            byte[] Bytes = new byte[File.Size];
            Buffer.BlockCopy(File.DecompressedImage, (int)File.BinaryOffset, Bytes, 0, (int)File.Size);

            return Bytes;
        }

        internal byte[] GetFile(Guid Guid)
        {
            EFI File = EFIs.Find(f => Guid == f.Guid);
            if (File == null)
            {
                return null;
            }

            byte[] Bytes = new byte[File.Size];
            Buffer.BlockCopy(File.DecompressedImage, (int)File.BinaryOffset, Bytes, 0, (int)File.Size);

            return Bytes;
        }*/

        private bool VerifyVolumeChecksum(byte[] Image, UInt32 Offset)
        {
            UInt16 VolumeHeaderSize = ByteOperations.ReadUInt16(Image, Offset + 0x30);
            byte[] Header = new byte[VolumeHeaderSize];
            Buffer.BlockCopy(Image, (int)Offset, Header, 0, VolumeHeaderSize);
            ByteOperations.WriteUInt16(Header, 0x32, 0); // Clear checksum
            UInt16 CurrentChecksum = ByteOperations.ReadUInt16(Image, Offset + 0x32);
            UInt16 NewChecksum = ByteOperations.CalculateChecksum16(Header, 0, VolumeHeaderSize);
            return CurrentChecksum == NewChecksum;
        }

        private bool VerifyFileChecksum(byte[] Image, UInt32 Offset)
        {
            // This function only checks fixed checksum-values 0x55 and 0xAA.

            const UInt16 FileHeaderSize = 0x18;
            UInt32 FileSize = ByteOperations.ReadUInt24(Image, Offset + 0x14);

            byte[] Header = new byte[FileHeaderSize - 1];
            Buffer.BlockCopy(Image, (int)Offset, Header, 0, FileHeaderSize - 1);
            ByteOperations.WriteUInt16(Header, 0x10, 0); // Clear checksum
            byte CurrentHeaderChecksum = ByteOperations.ReadUInt8(Image, Offset + 0x10);
            byte CalculatedHeaderChecksum = ByteOperations.CalculateChecksum8(Header, 0, (UInt32)FileHeaderSize - 1);

            if (CurrentHeaderChecksum != CalculatedHeaderChecksum)
            {
                return false;
            }

            byte FileAttribs = ByteOperations.ReadUInt8(Image, Offset + 0x13);
            byte CurrentFileChecksum = ByteOperations.ReadUInt8(Image, Offset + 0x11);
            if ((FileAttribs & 0x40) > 0)
            {
                // Calculate file checksum
                byte CalculatedFileChecksum = ByteOperations.CalculateChecksum8(Image, Offset + FileHeaderSize, FileSize - FileHeaderSize);
                if (CurrentFileChecksum != CalculatedFileChecksum)
                {
                    return false;
                }
            }
            else
            {
                // Fixed file checksum
                if ((CurrentFileChecksum != 0xAA) && (CurrentFileChecksum != 0x55))
                {
                    return false;
                }
            }

            return true;
        }
    }
}