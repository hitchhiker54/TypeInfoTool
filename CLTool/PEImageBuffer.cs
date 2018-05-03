using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SWBF2Tool
{
    public class PEImageBuffer
    {
        private IntPtr imageBase;
        private Int64 imageLength;
        private static byte[] buffer;
        RemoteProcess remoteProcess;

        public PEImageBuffer(RemoteProcess _remoteProcess)
        {
            remoteProcess = _remoteProcess;
            imageBase = remoteProcess.ImageBase;
            imageLength = remoteProcess.ImageSize;

            buffer = new byte[imageLength];
            remoteProcess.ReadBuffer(ref buffer, imageBase);
        }

        private bool DataCompare(Int64 pData, byte[] bMask)
        {
            for (int i = 0; i < bMask.Length; i++)
            {
                pData++;

                if (pData < (imageLength - bMask.Length + 1))
                {
                    if ((bMask[i] != 0) && (buffer[pData] != bMask[i]))
                    {
                        return false;
                    }
                }
                else return false;
            }

            return true;
        }

        public Int64 FindPattern(Int64 offsetFromBase, string sig)
        {
            byte[] byteMask = ParsePatternString(sig);

            if (offsetFromBase < 0)
            {
                return 0;
            }

            for (Int64 i = offsetFromBase; i < imageLength; i++)
            {
                if (DataCompare(i, byteMask))
                {
                    return imageBase.ToInt64() + i + 1;
                }
            }

            return 0;
        }

        private Int64 FindPattern(Int64 offsetFromBase, byte[] byteMask)
        {
            if (offsetFromBase < 0)
            {
                return 0;
            }

            for (Int64 i = offsetFromBase; i < imageLength; i++)
            {
                if (DataCompare(i, byteMask))
                {
                    return imageBase.ToInt64() + i + 1;
                }
            }

            return 0;
        }

        public Int64 FindOffset(string sig)
        {
            byte[] pattern = ParsePatternString(sig);
            Int64 Match = FindPattern(0, pattern);
            Int64 Offset = Match + 3;

            byte first = remoteProcess.Read<byte>((IntPtr)Offset + 4);

            Int32 Offset2 = remoteProcess.Read<Int32>((IntPtr)Offset);
            return Offset + Offset2 + 4;
        }

        public Int64 FindOffset(Int64 offsetFromBase, string sig)
        {
            byte[] pattern = ParsePatternString(sig);
            Int64 Match = FindPattern(offsetFromBase, pattern);
            Int64 Offset = Match + 3;

            byte first = remoteProcess.Read<byte>((IntPtr)Offset + 4);

            Int32 Offset2 = remoteProcess.Read<Int32>((IntPtr)Offset);
            return Offset + Offset2 + 4;
        }

        public Int64 DerefOffset(Int64 offset)
        {

            Int64 Offset = offset + 3;

            byte first = remoteProcess.Read<byte>((IntPtr)Offset + 4);

            Int32 Offset2 = remoteProcess.Read<Int32>((IntPtr)Offset);
            return Offset + Offset2 + 4;
        }

        public string AddressToSig(Int64 Address)
        {
            string tmp = "";
            string sig = "";

            for (int i = 0; i <= 64; i += 8)
            {
                tmp = ((Address >> i) & 0x00000000000000FF).ToString("X2");

                if (tmp == "00") tmp = "?";

                sig = $"{sig} {tmp}";
            }

            if (sig.ElementAt(0) == ' ')
            {
                sig = sig.Substring(1, sig.Length - 1);
            }

            return sig;
        }

        // from SigScanSharp by Striekcarl
        private byte[] ParsePatternString(string szPattern)
        {
            List<byte> patternbytes = new List<byte>();

            foreach (var szByte in szPattern.Split(' '))
                patternbytes.Add(szByte == "?" ? (byte)0x0 : Convert.ToByte(szByte, 16));

            return patternbytes.ToArray();
        }
    }
}
