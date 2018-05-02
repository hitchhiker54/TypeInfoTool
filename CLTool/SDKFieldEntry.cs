using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SWBF2Tool
{
    //[StructLayout(LayoutKind.Sequential, Size = 0x0018)]
    public struct SDKFieldEntry
    {
        public string fieldName;
        public int fieldOffset;
        public int fieldSize;
        public string fieldType;
        public int lastFieldOffset;
        public int lastFieldSize;
    }
}
