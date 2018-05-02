using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SWBF2Tool
{
    [StructLayout(LayoutKind.Sequential, Size = 0x0010, Pack = 0)]
    public class TestList
    {
        public IntPtr m_Head; //0x0000
        public IntPtr m_Tail; //0x0008
    }//Size=0x0010

    [StructLayout(LayoutKind.Sequential, Size = 0x0002, Pack = 0)]
    public struct MemberInfoFlags
    {
        public UInt16 m_FlagBits; //0x0000 
    };//Size=0x0002

    [StructLayout(LayoutKind.Sequential, Size = 0x0018, Pack = 0)]
    public class ModuleInfo
    {
        public IntPtr m_ModuleName; //0x0000 char*
        public IntPtr m_NextModule; //0x0008 ModuleInfo*
        public IntPtr m_TestList; //0x0010 TestList*
    };//Size=0x0018

    [StructLayout(LayoutKind.Sequential, Size = 0x000A, Pack = 0)]
    public class MemberInfoData
    {
        public IntPtr m_Name; //0x0000 char*
        //public MemberInfoFlags m_Flags; //0x0008
        public UInt16 m_Flags;

        public BasicTypesEnum GetEntryType()
        {
            return (BasicTypesEnum)((/*m_Flags.*/m_Flags & 0x01F0) >> 0x05);
        }
    };//Size=0x000A

    [StructLayout(LayoutKind.Sequential, Size = 0x0008, Pack = 0)]
    public class MemberInfo
    {
        public IntPtr m_InfoData; //0x0000 MemberInfoData*
    }

    [StructLayout(LayoutKind.Sequential, Size = 0x001E, Pack = 0)]
    public class TypeInfoData : MemberInfoData
    {
        public UInt16 m_TotalSize; //0x000A 
        private UInt32 pad_0x000C;
        public IntPtr m_Module; //0x0010 ModuleInfo*
                                       // new for swbfII
        public IntPtr m_pArrayTypeInfo; //0x0018 TypeInfo*

        public UInt16 m_Alignment; //0x0020 
        public UInt16 m_FieldCount; //0x0022 
        private UInt32 pad_0x0024;
    };//Size=0x0028

    [StructLayout(LayoutKind.Sequential, Size=0x000E, Pack = 0)]
    public class TypeInfo : MemberInfo
    {
        public IntPtr m_Next; //0x0008 TypeInfo*
        public UInt16 m_RuntimeId; //0x0010
        public UInt16 m_Flags; //0x0012
        private UInt32 pad_0x0014;
    }//Size=0x0018

    [StructLayout(LayoutKind.Sequential, Size = 0x000E, Pack = 0)]
    public class FieldInfoData : MemberInfoData
    {
        public UInt16 m_FieldOffset; //0x000A
        private UInt32 pad_0x0014;
        public IntPtr m_FieldTypePtr; //0x0010 TypeInfo*

    };//Size=0x0018

    [StructLayout(LayoutKind.Sequential, Size = 0x0008, Pack = 0)]
    public class FieldInfo : MemberInfo
    {
        public IntPtr m_DeclaringType; //0x0010 TypeInfo*
    }//Size=0x0018

    [StructLayout(LayoutKind.Sequential, Size = 0x0010)]
    public class ClassInfoData : TypeInfoData
    {
        //public IntPtr m_Name; //0x0000 char*
        ////public MemberInfoFlags m_Flags; //0x0008
        //public UInt16 m_FlagBits;
        //public BasicTypesEnum GetEntryType()
        //{
        //    return (BasicTypesEnum)((/*m_Flags.*/m_FlagBits & 0x01F0) >> 0x05);
        //}
        //public UInt16 m_TotalSize; //0x000A 
        //private UInt32 pad_0x000C;
        //public IntPtr m_Module; //0x0010 ModuleInfo*
        //                        // new for swbfII
        //public IntPtr m_pArrayTypeInfo; //0x0018 TypeInfo*

        //public UInt16 m_Alignment; //0x0020 
        //public UInt16 m_FieldCount; //0x0022 
        //private UInt32 pad_0x001C;
        public IntPtr m_SuperClass; //0x0028 ClassInfo*
        public IntPtr m_Fields; //0x0030 FieldInfoData*
    };//Size=0x0038

    [StructLayout(LayoutKind.Sequential, Size = 0x0038, Pack = 0)]
    public class ClassInfo : TypeInfo
    {
        private UInt64 pad_0018;
        //char pad_0018[32]; //0x0018
        private UInt64 pad_0020;
        private UInt64 pad_0028;
        private UInt64 pad_0030;
        public IntPtr m_Super; //0x0038 ClassInfo*
        public IntPtr m_DefaultInstance; //0x0040 void*
        public UInt16 m_ClassId; //0x0048
        public UInt16 m_LastSubClassId; //0x004A
        private UInt32 pad_0x004C;
    };//Size=0x0050

    [StructLayout(LayoutKind.Sequential, Size = 0x0008, Pack = 0)]
    public class ArrayTypeInfoData : TypeInfoData
    {
        public IntPtr m_ElementType; //0x0028 TypeInfo*
    };//Size=0x0030

    [StructLayout(LayoutKind.Sequential, Size = 0x0000, Pack = 0)]
    public class ArrayTypeInfo : TypeInfo
    {

    };//Size=0x0018

    [StructLayout(LayoutKind.Sequential, Size = 0x0008, Pack = 0)]
    public class EnumFieldInfoData : TypeInfoData
    {
        public IntPtr m_Fields; //0x0028   FieldInfoData*   
    };//Size=0x0030

    [StructLayout(LayoutKind.Sequential, Size = 0x0000, Pack = 0)]
    public class EnumFieldInfo : TypeInfo
    {

    };//Size=0x0018

    [StructLayout(LayoutKind.Sequential, Size = 0x0030, Pack = 0)]
    public class ValueTypeInfoData : TypeInfoData
    {
        //char pad_0028[40]; //0x0028
        private UInt64 pad_0028;
        private UInt64 pad_0030;
        private UInt64 pad_0038;
        private UInt64 pad_0040;
        private UInt64 pad_0048;
        public IntPtr m_Fields; //0x0050 FieldInfoData*

    };//Size=0x0058

    [StructLayout(LayoutKind.Sequential, Size = 0x0000, Pack = 0)]
    public class ValueTypeInfo : TypeInfo
    {

    };//Size=0x0018
}
