using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

/// <summary>
///
/// </summary>

namespace SWBF2Tool
{
    public class SDKClassInfo : SDKTypeInfo
    {
        public IntPtr ParentClass { get; protected set; } = IntPtr.Zero;
        public string ParentClassName { get; protected set; } = "";
        public List<SDKFieldEntry> Fields { get; protected set; } = new List<SDKFieldEntry>();
        public IntPtr DefaultInstance { get; protected set; } = IntPtr.Zero;
        public int ClassId { get; protected set; } = 0;
        public IntPtr VTable { get; protected set; } = IntPtr.Zero;
        public IntPtr GetType { get; protected set; } = IntPtr.Zero;

        // field offset + size logging for interfield padding
        private int lastFieldOffset = 0;
        private int lastFieldSize = 0;

        public SDKClassInfo() : base()
        {

        }

        public SDKClassInfo(IntPtr address, RemoteProcess remoteProcess, PEImageBuffer peImageBuffer)
        {
            ClassInfo typeInfo = remoteProcess.Read<ClassInfo>(address);
            ClassInfoData typeInfoData = remoteProcess.Read<ClassInfoData>(typeInfo.m_InfoData);

            Name = remoteProcess.ReadString(typeInfoData.m_Name, 255);
            ThisTypeInfo = address;
            Type = typeInfoData.GetEntryType();
            Flags = typeInfoData.m_Flags;
            Alignment = typeInfoData.m_Alignment;
            TotalSize = typeInfoData.m_TotalSize;
            FieldCount = typeInfoData.m_FieldCount;
            ParentClass = typeInfoData.m_SuperClass;
            var superClassInfo = new SDKTypeInfo(ParentClass, remoteProcess);
            ParentClassName = superClassInfo.Name;

            // debug
            if (Name == "PresenceMatchmakingServiceData")
            {
                Name = Name;
            }
            // end debug

            // fill fields list
            if (FieldCount > 0)
            {
                for (int i = 0; i < FieldCount; i++)
                {
                    var fieldInfoData = remoteProcess.Read<FieldInfoData>((IntPtr)((Int64)typeInfoData.m_Fields + (i * 0x18)));

                    SDKFieldEntry fieldEntry;
                    var fieldTypeInfo = new SDKTypeInfo(fieldInfoData.m_FieldTypePtr, remoteProcess);

                    // fix the odd field type with flags as 0x0000 or 0x2000
                    if ((fieldInfoData.m_Flags == 0) || (fieldInfoData.m_Flags == 0x2000))
                    {
                        fieldEntry.fieldType = fieldTypeInfo.FixTypeName(fieldTypeInfo.Name);
                    }
                    else
                    {
                        fieldEntry.fieldType = fieldTypeInfo.GetCppType(); //fieldTypeInfo.Name;
                    }
                    
                    fieldEntry.fieldName = remoteProcess.ReadString(fieldInfoData.m_Name, 255);
                    fieldEntry.fieldOffset = fieldInfoData.m_FieldOffset;
                    fieldEntry.fieldSize = fieldTypeInfo.TotalSize;
                    fieldEntry.lastFieldOffset = lastFieldOffset;
                    fieldEntry.lastFieldSize = lastFieldSize;

                    // fix error with some bools being flagged as int16_t
                    if ((fieldEntry.fieldType == "int16_t") && (fieldEntry.fieldSize == 1))
                    {
                        fieldEntry.fieldType = "bool";
                    }


                    Fields.Add(fieldEntry);

                    lastFieldOffset = fieldEntry.fieldOffset;
                    lastFieldSize = fieldTypeInfo.TotalSize;
                }

                // the field array isn't sorted in offset order so fix that
                Fields = Fields.OrderBy(x => x.fieldOffset).ToList();

                // check if pads needed
                for (int i = 1; i < FieldCount; i++)
                {
                    lastFieldOffset = Fields.ElementAt(i - 1).fieldOffset;
                    lastFieldSize = Fields.ElementAt(i - 1).fieldSize;

                    SDKFieldEntry fieldEntry;
                    fieldEntry = Fields.ElementAt(i);

                    fieldEntry.lastFieldOffset = lastFieldOffset;
                    fieldEntry.lastFieldSize = lastFieldSize;

                    Fields[i] = fieldEntry;
                }

                for (int i = 0; i < FieldCount; i++)
                {
                    SDKFieldEntry fieldEntry;

                    if (i == (FieldCount - 1))
                    {
                        // last class member so check against total size
                        if (TotalSize > (Fields.ElementAt(i).fieldOffset + Fields.ElementAt(i).fieldSize))
                        {
                            fieldEntry.fieldType = "char";
                            fieldEntry.fieldName = $"_0x{(Fields.ElementAt(i).fieldOffset + Fields.ElementAt(i).fieldSize).ToString("X4")}[{TotalSize - (Fields.ElementAt(i).fieldOffset + Fields.ElementAt(i).fieldSize)}]";
                            fieldEntry.fieldOffset = Fields.ElementAt(i).fieldOffset + Fields.ElementAt(i).fieldSize;
                            fieldEntry.fieldSize = TotalSize - (Fields.ElementAt(i).fieldOffset + Fields.ElementAt(i).fieldSize);
                            fieldEntry.lastFieldOffset = Fields.ElementAt(i).fieldOffset;
                            fieldEntry.lastFieldSize = Fields.ElementAt(i).fieldSize;

                            Fields.Add(fieldEntry);

                            FieldCount++;
                        }
                    }

                    if ((i == 0) && (ParentClass != IntPtr.Zero))
                    {
                        // first class member so check against parent size
                        if (superClassInfo.TotalSize < Fields.ElementAt(i).fieldOffset)
                        {
                            var debug = Fields.ElementAt(i).fieldOffset;
                            fieldEntry.fieldType = "char";
                            fieldEntry.fieldName = $"_0x{superClassInfo.TotalSize.ToString("X4")}[{Fields.ElementAt(i).fieldOffset - superClassInfo.TotalSize}]";
                            fieldEntry.fieldOffset = superClassInfo.TotalSize;
                            fieldEntry.fieldSize = Fields.ElementAt(i).fieldOffset - superClassInfo.TotalSize;
                            fieldEntry.lastFieldOffset = 0; // superClassInfo.TotalSize;
                            fieldEntry.lastFieldSize = superClassInfo.TotalSize;

                            Fields.Insert(0, fieldEntry);

                            i++;
                            FieldCount++;
                        }
                    }
                    else
                    {
                        // inter-field pads. seems to be correct now :)
                        if (Fields.ElementAt(i).fieldOffset > (Fields.ElementAt(i).lastFieldOffset + Fields.ElementAt(i).lastFieldSize))
                        {
                            fieldEntry.fieldType = "char";
                            fieldEntry.fieldName = $"_0x{(Fields.ElementAt(i).lastFieldOffset + Fields.ElementAt(i).lastFieldSize).ToString("X4")}[{Fields.ElementAt(i).fieldOffset - (Fields.ElementAt(i).lastFieldOffset + Fields.ElementAt(i).lastFieldSize)}]";
                            fieldEntry.fieldOffset = Fields.ElementAt(i).lastFieldOffset + Fields.ElementAt(i).lastFieldSize;
                            fieldEntry.fieldSize = Fields.ElementAt(i).fieldOffset - (Fields.ElementAt(i).lastFieldOffset + Fields.ElementAt(i).lastFieldSize);
                            fieldEntry.lastFieldOffset = Fields.ElementAt(i).fieldOffset;
                            fieldEntry.lastFieldSize = Fields.ElementAt(i).fieldSize;

                            Fields.Insert(i, fieldEntry);

                            i++;
                            FieldCount++;
                        }
                    }
                }
            }

            RuntimeId = typeInfo.m_RuntimeId;
            Next = typeInfo.m_Next;
            DefaultInstance = typeInfo.m_DefaultInstance;
            ClassId = typeInfo.m_ClassId;
            GetVtable(remoteProcess, peImageBuffer);
        }

        private void GetVtable(RemoteProcess remoteProcess, PEImageBuffer peImageBuffer)
        {
            if (DefaultInstance != IntPtr.Zero)
            {
                VTable = remoteProcess.Read<IntPtr>(DefaultInstance);
            }
            else
            {
                var foundGetType = false;
                Int64 start = 0;
                Int64 possibleGetType = 0;

                while (foundGetType == false)
                {
                    possibleGetType = peImageBuffer.FindPattern(start, "48 8D 05 ? ? ? ? c3");
                    var deRef = peImageBuffer.DerefOffset(possibleGetType);

                    if (start >= remoteProcess.ImageSize)
                    {
                        break;
                    }

                    if (deRef != ThisTypeInfo.ToInt64())
                    {
                        start = possibleGetType - remoteProcess.ImageBase.ToInt64() + 8;
                    }
                    else
                    {
                        foundGetType = true;
                    }

                    if ((start >= remoteProcess.ImageSize) || (start < 0))
                    {
                        VTable = IntPtr.Zero;
                        break;
                    }
                }

                // look for pointer to the GetType we found
                if (foundGetType)
                {
                    GetType = (IntPtr)possibleGetType;
                    VTable = (IntPtr)peImageBuffer.FindPattern(start, peImageBuffer.AddressToSig(possibleGetType));
                }
            }

        }
    }
}
