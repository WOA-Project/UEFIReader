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
using System;
using System.Collections.Generic;
using System.Linq;

namespace UEFIReader
{
    internal class EFI
    {
        internal Guid Guid;
        internal string Name;
        internal int Type;
        internal UInt32 Size;
        internal UInt32 FileOffset;
        internal UInt32 SectionOffset;
        internal UInt32 BinaryOffset;
        public byte[] DecompressedImage;
    }

    internal class UEFI
    {
        internal List<EFI> EFIs = new();

        // First 0x28 bytes are Qualcomm partition header
        // Inside the attributes of the VolumeHeader, the Volume-alignment is set to 8 (on Windows Phone UEFI images)
        // The Volume always starts right after the Qualcomm header at position 0x28.
        // So the VolumeHeader-alignment is always complied.

        internal UEFI(byte[] UefiBinary)
        {
            UInt32? Offset = ByteOperations.FindAscii(UefiBinary, "_FVH");
            UInt32 VolumeHeaderOffset = Offset == null ? throw new BadImageFormatException() : (UInt32)Offset - 0x28;

            HandleVolumeImage(UefiBinary, VolumeHeaderOffset);
        }

        internal void HandleVolumeImage(byte[] Input, UInt32 Offset)
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

            HandleFileLoop(Input, FileHeaderOffset, Offset + VolumeHeaderSize);
        }

        internal void HandleFileLoop(byte[] Input, UInt32 Offset, UInt32 Base)
        {
            if (!VerifyFileChecksum(Input, Offset))
            {
                return;
                //throw new BadImageFormatException();
            }

            do
            {
                (byte FileType, uint FileSize) = ReadFileMetadata(Input, Offset);

                switch (FileType)
                {
                    case 0x02: // EFI_FV_FILETYPE_FREEFORM
                        {
                            Console.WriteLine("EFI_FV_FILETYPE_FREEFORM");
                            break;
                        }
                    case 0x03: // EFI_FV_FILETYPE_SECURITY_CORE
                        {
                            Console.WriteLine("EFI_FV_FILETYPE_SECURITY_CORE");
                            break;
                        }
                    case 0x05: // EFI_FV_FILETYPE_DXE_CORE
                        {
                            Console.WriteLine("EFI_FV_FILETYPE_DXE_CORE");
                            break;
                        }
                    case 0x07: // EFI_FV_FILETYPE_DRIVER
                        {
                            Console.WriteLine("EFI_FV_FILETYPE_DRIVER");
                            break;
                        }
                    case 0x09: // EFI_FV_FILETYPE_APPLICATION
                        {
                            Console.WriteLine("EFI_FV_FILETYPE_APPLICATION");
                            break;
                        }
                    case 0x0B: // EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE
                        {
                            Console.WriteLine("EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE");
                            HandleSectionLoop(Input, Offset + 0x18, Offset + 0x18);
                            break;
                        }
                    case 0xF0: // EFI_FV_FILETYPE_FFS_PAD
                        {
                            Console.WriteLine("EFI_FV_FILETYPE_FFS_PAD");
                            break;
                        }
                    default:
                        {
                            Console.WriteLine("Unsupported file type! " + FileType);
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
        }

        internal void HandleSectionLoop(byte[] Input, UInt32 Offset, UInt32 Base)
        {
            do
            {
                (uint SectionSize, byte SectionType) = ReadSectionMetadata(Input, Offset);

                switch (SectionType)
                {
                    case 0x02: // EFI_SECTION_GUID_DEFINED
                        {
                            Console.WriteLine("EFI_SECTION_GUID_DEFINED");
                            ParseGuidDefinedSection(Input, Offset, Base);
                            break;
                        }
                    case 0x17: // EFI_SECTION_FIRMWARE_VOLUME_IMAGE
                        {
                            Console.WriteLine("EFI_SECTION_FIRMWARE_VOLUME_IMAGE");
                            HandleVolumeImage(Input, Offset + 4);
                            break;
                        }
                    case 0x19: // EFI_SECTION_RAW
                        {
                            Console.WriteLine("EFI_SECTION_RAW");
                            break;
                        }
                    default:
                        {
                            Console.WriteLine("Unsupported section type! " + SectionType);
                            break;
                        }
                }

                Offset += SectionSize;

                // Offset must be Align 4
                Offset = ByteOperations.Align(Base, Offset, 4);
            }
            while (Offset < Input.Length);
        }

        internal void HandleVolumeImage2(byte[] Input, UInt32 Offset)
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

            EFI CurrentEFI;
            do
            {
                (byte FileType, uint FileSize) = ReadFileMetadata(Input, FileHeaderOffset);

                if ((FileHeaderOffset + 0x18) >= (Offset + VolumeSize))
                {
                    break;
                }

                bool ContentFound = false;
                for (int i = 0; i < 0x18; i++)
                {
                    if (Input[FileHeaderOffset + i] != PaddingByteValue)
                    {
                        ContentFound = true;
                        break;
                    }
                }
                if (!ContentFound)
                {
                    break;
                }

                if ((FileHeaderOffset + FileSize) >= (Offset + VolumeSize))
                {
                    break;
                }

                if (!VerifyFileChecksum(Input, FileHeaderOffset))
                {
                    throw new BadImageFormatException();
                }

                CurrentEFI = new EFI
                {
                    Type = FileType
                };
                byte[] FileGuidBytes = new byte[0x10];
                Buffer.BlockCopy(Input, (int)FileHeaderOffset + 0x00, FileGuidBytes, 0, 0x10);
                CurrentEFI.Guid = new Guid(FileGuidBytes);

                // Parse sections of the EFI
                CurrentEFI.FileOffset = FileHeaderOffset;
                CurrentEFI.DecompressedImage = Input;
                UInt32 DecompressedSectionHeaderOffset = FileHeaderOffset + 0x18;
                do
                {
                    (uint SectionSize, byte SectionType) = ReadSectionMetadata(Input, DecompressedSectionHeaderOffset);

                    // SectionTypes that are relevant here:
                    // 0x10 = PE File
                    // 0x19 = RAW
                    // 0x15 = Description
                    // Not all section headers in the UEFI specs are 4 bytes long,
                    // but the sections that are used in Windows Phone EFI's all have a header of 4 bytes.
                    if (SectionType == 0x15)
                    {
                        CurrentEFI.Name = ByteOperations.ReadUnicodeString(Input, DecompressedSectionHeaderOffset + 0x04, SectionSize - 0x04).TrimEnd(new char[] { (char)0, ' ' });
                    }
                    else if ((SectionType == 0x10) || (SectionType == 0x19))
                    {
                        CurrentEFI.SectionOffset = DecompressedSectionHeaderOffset;
                        CurrentEFI.BinaryOffset = DecompressedSectionHeaderOffset + 0x04;
                        CurrentEFI.Size = SectionSize - 0x04;
                    }

                    DecompressedSectionHeaderOffset += SectionSize;

                    // SectionHeaderOffset in File-body must be Align 4
                    DecompressedSectionHeaderOffset = ByteOperations.Align(FileHeaderOffset + 0x18, DecompressedSectionHeaderOffset, 4);
                }
                while (DecompressedSectionHeaderOffset < (FileHeaderOffset + FileSize));

                FileHeaderOffset += FileSize;

                // FileHeaderOffset in Volume-body must be Align 8
                // In the file-header-attributes the file-alignment relative to the start of the volume is always set to 1,
                // so that alignment can be ignored.
                FileHeaderOffset = ByteOperations.Align(Offset + VolumeHeaderSize, FileHeaderOffset, 8);

                EFIs.Add(CurrentEFI);
            }
            while (FileHeaderOffset < (Offset + VolumeSize));
        }

        internal (uint SectionSize, byte SectionType) ReadSectionMetadata(byte[] Input, UInt32 Offset)
        {
            uint SectionSize = ByteOperations.ReadUInt24(Input, Offset + 0x00);
            byte SectionType = ByteOperations.ReadUInt8(Input, Offset + 0x03);

            return (SectionSize, SectionType);
        }

        internal (byte FileType, uint FileSize) ReadFileMetadata(byte[] Input, UInt32 Offset)
        {
            byte FileType = ByteOperations.ReadUInt8(Input, Offset + 0x12);
            uint FileSize = ByteOperations.ReadUInt24(Input, Offset + 0x14);

            return (FileType, FileSize);
        }

        internal void ParseGuidDefinedSection(byte[] Input, UInt32 Offset, UInt32 Base)
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

            HandleSectionLoop(DecompressedImage, 0, Base);
        }

        internal byte[] GetFile(string Name)
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
        }

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