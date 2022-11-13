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

using System.Diagnostics;
using System.Text.RegularExpressions;

namespace UEFIReader
{
    internal class EFI
    {
        internal Guid Guid;
        internal string? Type;
        public EFISection[]? SectionElements;
    }

    internal class EFISection
    {
        internal string? Name;
        internal string? Type;
        public byte[]? DecompressedImage;
    }

    internal class UEFI
    {
        internal List<EFI> EFIs = new();

        // First 0x28 bytes are Qualcomm partition header
        // Inside the attributes of the VolumeHeader, the Volume-alignment is set to 8 (on Windows Phone UEFI images)
        // The Volume always starts right after the Qualcomm header at position 0x28.
        // So the VolumeHeader-alignment is always complied.

        internal HashSet<Guid> LoadPriority = new();

        internal string BuildId = "";

        internal UEFI(byte[] UefiBinary)
        {
            uint? Offset = ByteOperations.FindAscii(UefiBinary, "_FVH");
            uint VolumeHeaderOffset = Offset == null ? throw new BadImageFormatException() : (uint)Offset - 0x28;

            EFIs.AddRange(HandleVolumeImage(UefiBinary, VolumeHeaderOffset));

            var buildIds = TryGetBuildPath(UefiBinary);
            if (buildIds.Count() > 0)
            {
                BuildId = buildIds[0];
            }
        }

        internal void ExtractUEFI(string Output)
        {
            ExtractDXEs(Output);
            ExtractAPRIORI(Output);
        }

        internal string[] TryGetFilePath(byte[] Data)
        {
            Regex regex = new("[a-zA-Z/\\\\0-9_\\-\\.]*\\.dll\\b");
            string[] results = regex.Matches(System.Text.Encoding.ASCII.GetString(Data)).Select(x => x.Value).ToArray();
            return results.Select(s => NormalizeBuildPath(s)).Where(s => s.Count(x => x == '/') > 1).ToArray();
        }

        internal string[] TryGetBuildPath(byte[] Data)
        {
            Regex regex = new("QC_IMAGE_VERSION_STRING=[a-zA-Z/\\\\0-9_\\-\\.]*\\b");
            string[] results = regex.Matches(System.Text.Encoding.ASCII.GetString(Data)).Select(x => x.Value).ToArray();
            return results.Select(s => s.Replace("QC_IMAGE_VERSION_STRING=", "")).ToArray();
        }

        internal string NormalizeBuildPath(string path)
        {
            if (path.Contains("ARM"))
            {
                return path.Replace("\\", "/").Split("/ARM/")[^1];
            }
            else if (path.Contains("AARCH64"))
            {
                return path.Replace("\\", "/").Split("/AARCH64/")[^1];
            }
            else
            {
                return path.Replace("\\", "/");
            }
        }

        internal void ExtractDXEs(string Output)
        {
            List<string> dxeLoadList = new();
            List<string> dxeIncludeList = new();

            foreach (EFI element in EFIs)
            {
                if (element.SectionElements.Any(x => IsSectionWithPath(x)))
                {
                    EFISection[] sectionsWithPaths = element.SectionElements.Where(x => IsSectionWithPath(x)).ToArray();

                    List<string> filePathsForElement = new();
                    foreach (EFISection section in sectionsWithPaths)
                    {
                        filePathsForElement.AddRange(TryGetFilePath(section.DecompressedImage));
                    }

                    string outputPath = "";
                    string moduleName = "";
                    string baseName = "";

                    EFISection[] uis = element.SectionElements.Where(x => IsSectionWithUI(x)).ToArray();

                    if (filePathsForElement.Count > 0)
                    {
                        outputPath = string.Join("/", filePathsForElement[0].Split("/")[..^3]).Replace('/', Path.DirectorySeparatorChar);
                        moduleName = filePathsForElement[0].Split("/")[^3];

                        if (uis.Length > 1)
                        {
                            throw new BadImageFormatException();
                        }
                        else
                        {
                            baseName = uis.Length == 1 ? uis[0].Name : moduleName;
                        }
                    }
                    else
                    {
                        if (uis.Length > 1)
                        {
                            throw new BadImageFormatException();
                        }
                        else if (uis.Length == 1)
                        {
                            baseName = uis[0].Name;
                            moduleName = baseName.Replace(" ", "_");
                            outputPath = baseName.Replace(" ", "_");
                        }
                    }

                    string combinedPath = Path.Combine(Output, outputPath);
                    if (!Directory.Exists(combinedPath))
                    {
                        _ = Directory.CreateDirectory(combinedPath);
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

                    bool hasDepex = element.SectionElements.Any(x => x.Type == "DXE_DEPEX");

                    string infoutput = "# ****************************************************************************\r\n" +
                                       "# AUTOGENERATED BY UEFIReader\r\n" +
                                      $"# AUTOGENED AS {moduleName + ".inf"}\r\n" +
                                       "# DO NOT MODIFY\r\n" +
                                      $"# GENERATED ON: {DateTime.UtcNow.ToString("u")}\r\n" +
                                       "\r\n" +
                                       "[Defines]\r\n" +
                                       "  INF_VERSION    = 0x0001001B\r\n" +
                                      $"  BASE_NAME      = {baseName}\r\n" +
                                      $"  FILE_GUID      = {element.Guid.ToString().ToUpper()}\r\n" +
                                      $"  MODULE_TYPE    = {moduleType}\r\n" +
                                       "  VERSION_STRING = 1.0\r\n" +
                                       (hasDepex ? "  ENTRY_POINT    = EfiEntry\r\n" : "") +
                                       "\r\n" +
                                       "[Binaries.AARCH64]";

                    foreach (EFISection item in element.SectionElements)
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
                        string outputFileName = $"{moduleName}.{extension}";

                        infoutput += $"\r\n   {type}|{outputFileName}|*";

                        if (File.Exists(Path.Combine(combinedPath, outputFileName)))
                        {
                            throw new Exception("File Conflict Detected");
                        }
                        File.WriteAllBytes(Path.Combine(combinedPath, outputFileName), item.DecompressedImage);
                    }

                    infoutput += "\r\n" + 
                                 "\r\n" + 
                                 (hasDepex ? "[Depex]\r\n" +
                                             "  TRUE\r\n" : "") +
                                 "# AUTOGEN ENDS\r\n" +
                                 "# ****************************************************************************\r\n";

                    File.WriteAllText(Path.Combine(combinedPath, moduleName + ".inf"), infoutput);

                    dxeLoadList.Add($"INF {Path.Combine(outputPath, moduleName + ".inf").Replace("\\", "/")}");
                    dxeIncludeList.Add($"{Path.Combine(outputPath, moduleName + ".inf").Replace("\\", "/")}");
                }
                else if (element.SectionElements.Any(x => IsSectionWithUI(x)))
                {
                    EFISection[] uis = element.SectionElements.Where(x => IsSectionWithUI(x)).ToArray();

                    if (uis.Length > 1)
                    {
                        throw new BadImageFormatException();
                    }

                    string fileName = uis[0].Name;
                    dxeLoadList.Add("");
                    dxeLoadList.Add($"FILE FREEFORM = {element.Guid.ToString().ToUpper()} {{");
                    foreach (EFISection section in element.SectionElements)
                    {
                        string el = string.IsNullOrEmpty(section.Name) ? fileName : section.Name;

                        if (section.Type == "RAW")
                        {
                            string combinedPath = Path.Combine(Output, "RawFiles");
                            string realFileName = fileName.Replace(" ", "_").Replace('\\', Path.DirectorySeparatorChar).Replace('/', Path.DirectorySeparatorChar);
                            string filedst = Path.Combine(combinedPath, realFileName);

                            if (!Directory.Exists(Path.GetDirectoryName(filedst)))
                            {
                                _ = Directory.CreateDirectory(Path.GetDirectoryName(filedst));
                            }

                            File.WriteAllBytes(Path.Combine(combinedPath, filedst), section.DecompressedImage);
                            dxeLoadList.Add($"    SECTION {section.Type} = RawFiles/{fileName.Replace(" ", "_").Replace('\\', '/')}");
                        }
                        else if (section.Type == "UI")
                        {
                            dxeLoadList.Add($"    SECTION {section.Type} = \"{el}\"");
                        }
                    }
                    dxeLoadList.Add("}");
                    dxeLoadList.Add("");
                }
            }

            File.WriteAllLines(Path.Combine(Output, "DXE.dsc.inc"), dxeIncludeList);
            File.WriteAllLines(Path.Combine(Output, "DXE.inc"), dxeLoadList);
        }

        internal void ExtractAPRIORI(string Output)
        {
            List<string> aprioriLoadList = new()
            {
                "APRIORI DXE {"
            };

            foreach (EFI element in EFIs)
            {
                if (element.SectionElements.Any(x => IsSectionWithPath(x)))
                {
                    EFISection[] sectionsWithPaths = element.SectionElements.Where(x => IsSectionWithPath(x)).ToArray();

                    List<string> filePathsForElement = new();
                    foreach (EFISection? section in sectionsWithPaths)
                    {
                        filePathsForElement.AddRange(TryGetFilePath(section.DecompressedImage));
                    }

                    string outputPath = "";
                    string moduleName = "";
                    string baseName = "";

                    EFISection[] uis = element.SectionElements.Where(x => IsSectionWithUI(x)).ToArray();

                    if (filePathsForElement.Count > 0)
                    {
                        outputPath = string.Join("/", filePathsForElement[0].Split("/")[..^3]).Replace('/', Path.DirectorySeparatorChar);
                        moduleName = filePathsForElement[0].Split("/")[^3];

                        if (uis.Length > 1)
                        {
                            throw new BadImageFormatException();
                        }
                        else
                        {
                            baseName = uis.Length == 1 ? uis[0].Name : moduleName;
                        }
                    }
                    else
                    {
                        if (uis.Length > 1)
                        {
                            throw new BadImageFormatException();
                        }
                        else if (uis.Length == 1)
                        {
                            baseName = uis[0].Name;
                            moduleName = baseName.Replace(" ", "_");
                            outputPath = baseName.Replace(" ", "_");
                        }
                    }

                    if (LoadPriority.Contains(element.Guid))
                    {
                        aprioriLoadList.Add($"    INF {Path.Combine(outputPath, moduleName + ".inf").Replace("\\", "/")}");
                    }
                }
            }

            aprioriLoadList.Add("}");

            File.WriteAllLines(Path.Combine(Output, "APRIORI.inc"), aprioriLoadList);
        }

        internal bool IsSectionWithPath(EFISection section)
        {
            return section.Type is not "UI" and not "DXE_DEPEX" and not "RAW" and not "PEI_DEPEX";
        }

        internal bool IsSectionWithUI(EFISection section)
        {
            return section.Type == "UI";
        }

        internal EFI[] HandleVolumeImage(byte[] Input, uint Offset)
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

            uint VolumeSize = ByteOperations.ReadUInt32(Input, Offset + 0x20); // TODO: This is actually a QWORD
            ushort VolumeHeaderSize = ByteOperations.ReadUInt16(Input, Offset + 0x30);
            byte PaddingByteValue = (ByteOperations.ReadUInt32(Input, Offset + 0x2C) & 0x00000800) > 0 ? (byte)0xFF : (byte)0x00; // EFI_FVB_ERASE_POLARITY = 0x00000800

            uint FileHeaderOffset = Offset + VolumeHeaderSize;

            byte[] buffer = new byte[VolumeSize - VolumeHeaderSize];
            Buffer.BlockCopy(Input, (int)FileHeaderOffset, buffer, 0, buffer.Length);

            return HandleFileLoop(buffer, 0, FileHeaderOffset);
        }

        internal EFI[] HandleFileLoop(byte[] Input, uint Offset, uint Base)
        {
            List<EFI> fileElements = new();

            if (!VerifyFileChecksum(Input, Offset))
            {
                throw new BadImageFormatException();
            }

            do
            {
                if (Offset + 0x18 > Input.Length)
                {
                    //throw new BadImageFormatException();
                    return fileElements.ToArray();
                }

                (byte FileType, uint FileSize, Guid FileGuid) = ReadFileMetadata(Input, Offset);

                if (Offset + FileSize > Input.Length || FileSize == 0)
                {
                    //throw new BadImageFormatException();
                    return fileElements.ToArray();
                }

                switch (FileType)
                {
                    case 0x02: // EFI_FV_FILETYPE_FREEFORM
                        {
                            if (FileGuid == new Guid("FC510EE7-FFDC-11D4-BD41-0080C73C8881"))
                            {
                                Debug.WriteLine("EFI_FV_FILETYPE_DXE_APRIORI");

                                byte[] buffer = new byte[FileSize - 0x18];
                                Buffer.BlockCopy(Input, (int)Offset + 0x18, buffer, 0, buffer.Length);

                                EFISection[] elements = HandleSectionLoop(buffer, 0, Offset + 0x18);

                                if (elements.Count() > 0 && elements[0].Type == "RAW")
                                {
                                    for (uint i = 0; i < elements[0].DecompressedImage.Length; i += 16)
                                    {
                                        Guid dependencyGuid = ByteOperations.ReadGuid(elements[0].DecompressedImage, i);
                                        Debug.WriteLine(dependencyGuid.ToString().ToUpper());
                                        _ = LoadPriority.Add(dependencyGuid);
                                    }
                                }
                            }
                            else
                            {
                                Debug.WriteLine("EFI_FV_FILETYPE_FREEFORM");

                                byte[] buffer = new byte[FileSize - 0x18];
                                Buffer.BlockCopy(Input, (int)Offset + 0x18, buffer, 0, buffer.Length);

                                EFISection[] elements = HandleSectionLoop(buffer, 0, Offset + 0x18);
                                fileElements.Add(new() { Type = "FREEFORM", Guid = FileGuid, SectionElements = elements });
                            }

                            break;
                        }
                    case 0x03: // EFI_FV_FILETYPE_SECURITY_CORE
                        {
                            Debug.WriteLine("EFI_FV_FILETYPE_SECURITY_CORE");

                            byte[] buffer = new byte[FileSize - 0x18];
                            Buffer.BlockCopy(Input, (int)Offset + 0x18, buffer, 0, buffer.Length);

                            EFISection[] elements = HandleSectionLoop(buffer, 0, Offset + 0x18);
                            fileElements.Add(new() { Type = "SECURITY_CORE", Guid = FileGuid, SectionElements = elements });

                            break;
                        }
                    case 0x05: // EFI_FV_FILETYPE_DXE_CORE
                        {
                            Debug.WriteLine("EFI_FV_FILETYPE_DXE_CORE");

                            byte[] buffer = new byte[FileSize - 0x18];
                            Buffer.BlockCopy(Input, (int)Offset + 0x18, buffer, 0, buffer.Length);

                            EFISection[] elements = HandleSectionLoop(buffer, 0, Offset + 0x18);
                            fileElements.Add(new() { Type = "DXE_CORE", Guid = FileGuid, SectionElements = elements });

                            break;
                        }
                    case 0x07: // EFI_FV_FILETYPE_DRIVER
                        {
                            Debug.WriteLine("EFI_FV_FILETYPE_DRIVER");

                            byte[] buffer = new byte[FileSize - 0x18];
                            Buffer.BlockCopy(Input, (int)Offset + 0x18, buffer, 0, buffer.Length);

                            EFISection[] elements = HandleSectionLoop(buffer, 0, Offset + 0x18);
                            fileElements.Add(new() { Type = "DRIVER", Guid = FileGuid, SectionElements = elements });

                            break;
                        }
                    case 0x09: // EFI_FV_FILETYPE_APPLICATION
                        {
                            Debug.WriteLine("EFI_FV_FILETYPE_APPLICATION");

                            byte[] buffer = new byte[FileSize - 0x18];
                            Buffer.BlockCopy(Input, (int)Offset + 0x18, buffer, 0, buffer.Length);

                            EFISection[] elements = HandleSectionLoop(buffer, 0, Offset + 0x18);
                            fileElements.Add(new() { Type = "APPLICATION", Guid = FileGuid, SectionElements = elements });

                            break;
                        }
                    case 0x0B: // EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE
                        {
                            Debug.WriteLine("EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE");

                            byte[] buffer = new byte[FileSize - 0x18];
                            Buffer.BlockCopy(Input, (int)Offset + 0x18, buffer, 0, buffer.Length);

                            EFISection[] elements = HandleSectionLoop(buffer, 0, Offset + 0x18);
                            foreach (EFISection element in elements)
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
                            throw new BadImageFormatException();
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

        internal byte[] ReadSectionDataBuffer(byte[] Input, uint Offset)
        {
            (uint SectionSize, _) = ReadSectionMetadata(Input, Offset);

            byte[] buffer = new byte[SectionSize - 0x04];
            Buffer.BlockCopy(Input, (int)Offset + 0x04, buffer, 0, buffer.Length);

            return buffer;
        }

        internal EFISection[] HandleSectionLoop(byte[] Input, uint Offset, uint Base)
        {
            List<EFISection> fileElements = new();

            do
            {
                if (Offset + 0x04 > Input.Length)
                {
                    throw new BadImageFormatException();
                }

                (uint SectionSize, byte SectionType) = ReadSectionMetadata(Input, Offset);

                if (Offset + SectionSize > Input.Length || SectionSize == 0)
                {
                    throw new BadImageFormatException();
                }

                switch (SectionType)
                {
                    case 0x02: // EFI_SECTION_GUID_DEFINED
                        {
                            Debug.WriteLine("EFI_SECTION_GUID_DEFINED");
                            fileElements.AddRange(ParseGuidDefinedSection(Input, Offset, Base));
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
                    case 0x18: // EFI_SECTION_FREEFORM_SUBTYPE_GUID
                        {
                            Debug.WriteLine("EFI_SECTION_FREEFORM_SUBTYPE_GUID");
                            fileElements.Add(new() { Type = "RAW", DecompressedImage = ReadSectionDataBuffer(Input, Offset) });
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
                            throw new BadImageFormatException();
                        }
                }

                Offset += SectionSize;

                // Offset must be Align 4
                Offset = ByteOperations.Align(Base, Offset, 4);
            }
            while (Offset < Input.Length);

            return fileElements.ToArray();
        }

        internal (uint SectionSize, byte SectionType) ReadSectionMetadata(byte[] Input, uint Offset)
        {
            uint SectionSize = ByteOperations.ReadUInt24(Input, Offset + 0x00);
            byte SectionType = ByteOperations.ReadUInt8(Input, Offset + 0x03);

            return (SectionSize, SectionType);
        }

        internal (byte FileType, uint FileSize, Guid FileGuid) ReadFileMetadata(byte[] Input, uint Offset)
        {
            byte[] FileGuidBytes = new byte[0x10];
            Buffer.BlockCopy(Input, (int)Offset + 0x00, FileGuidBytes, 0, 0x10);
            Guid FileGuid = new(FileGuidBytes);

            byte FileType = ByteOperations.ReadUInt8(Input, Offset + 0x12);
            uint FileSize = ByteOperations.ReadUInt24(Input, Offset + 0x14);

            return (FileType, FileSize, FileGuid);
        }

        internal EFISection[] ParseGuidDefinedSection(byte[] Input, uint Offset, uint Base)
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
            Guid SectionGuid = new(SectionGuidBytes);
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

        private bool VerifyVolumeChecksum(byte[] Image, uint Offset)
        {
            ushort VolumeHeaderSize = ByteOperations.ReadUInt16(Image, Offset + 0x30);
            byte[] Header = new byte[VolumeHeaderSize];
            Buffer.BlockCopy(Image, (int)Offset, Header, 0, VolumeHeaderSize);
            ByteOperations.WriteUInt16(Header, 0x32, 0); // Clear checksum
            ushort CurrentChecksum = ByteOperations.ReadUInt16(Image, Offset + 0x32);
            ushort NewChecksum = ByteOperations.CalculateChecksum16(Header, 0, VolumeHeaderSize);
            return CurrentChecksum == NewChecksum;
        }

        private bool VerifyFileChecksum(byte[] Image, uint Offset)
        {
            // This function only checks fixed checksum-values 0x55 and 0xAA.

            const ushort FileHeaderSize = 0x18;
            uint FileSize = ByteOperations.ReadUInt24(Image, Offset + 0x14);

            byte[] Header = new byte[FileHeaderSize - 1];
            Buffer.BlockCopy(Image, (int)Offset, Header, 0, FileHeaderSize - 1);
            ByteOperations.WriteUInt16(Header, 0x10, 0); // Clear checksum
            byte CurrentHeaderChecksum = ByteOperations.ReadUInt8(Image, Offset + 0x10);
            byte CalculatedHeaderChecksum = ByteOperations.CalculateChecksum8(Header, 0, (uint)FileHeaderSize - 1);

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
                if (CurrentFileChecksum is not 0xAA and not 0x55)
                {
                    return false;
                }
            }

            return true;
        }
    }
}