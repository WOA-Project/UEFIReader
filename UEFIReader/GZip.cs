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

using System.IO.Compression;

namespace UEFIReader
{
    internal static class GZip
    {
        internal static byte[] Decompress(byte[] Input, ulong Offset, ulong InputSize)
        {
            MemoryStream InStream = new(Input, (int)Offset, (int)InputSize);
            MemoryStream OutStream = new();

            GZipStream GZipStream = new(InStream, CompressionMode.Decompress, false);

            GZipStream.CopyTo(OutStream);

            byte[] Output = new byte[OutStream.Length];
            Buffer.BlockCopy(OutStream.GetBuffer(), 0, Output, 0, (int)OutStream.Length);

            OutStream.Flush();
            OutStream.Close();
            GZipStream.Close();
            InStream.Close();

            return Output;
        }

        internal static byte[] Compress(byte[] Input, ulong Offset, ulong InputSize)
        {
            MemoryStream InStream = new(Input, (int)Offset, (int)InputSize);
            MemoryStream OutStream = new();

            GZipStream GZipStream = new(InStream, CompressionMode.Compress, false);

            GZipStream.CopyTo(OutStream);

            byte[] Output = new byte[OutStream.Length];
            Buffer.BlockCopy(OutStream.GetBuffer(), 0, Output, 0, (int)OutStream.Length);

            OutStream.Flush();
            OutStream.Close();
            GZipStream.Close();
            InStream.Close();

            return Output;
        }
    }
}