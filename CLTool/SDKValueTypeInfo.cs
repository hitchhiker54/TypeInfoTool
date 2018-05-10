using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

/* 
Error D:\dump\swbf2\26-4-18 update\test\Enums.h,10051: Type 'CutsceneActorType' is already defined
  included from D:\dump\swbf2\26-4-18 update\test\idaimport.h, 7
Error D:\dump\swbf2\26-4-18 update\test\Enums.h,13101: Type 'DSJetpackMovementMode' is already defined
Error D:\dump\swbf2\26-4-18 update\test\Enums.h,13835: Type 'AIPathLinkDirection' is already defined
Error D:\dump\swbf2\26-4-18 update\test\Structs.h,8032: Syntax error near: char
  included from D:\dump\swbf2\26-4-18 update\test\idaimport.h, 8
Error D:\dump\swbf2\26-4-18 update\test\Structs.h,8035: Syntax error near: }
 * */

namespace SWBF2Tool
{
    public class SDKValueTypeInfo : SDKTypeInfo
    {
        public List<SDKFieldEntry> Fields { get; protected set; } = new List<SDKFieldEntry>();

        // field offset + size logging for interfield padding
        public int lastFieldOffset = 0;
        public int lastFieldSize = 0;

        public SDKValueTypeInfo() : base()
        {

        }

        public SDKValueTypeInfo(IntPtr address, RemoteProcess remoteProcess)
        {
            ValueTypeInfo typeInfo = remoteProcess.Read<ValueTypeInfo>(address);
            ValueTypeInfoData typeInfoData = remoteProcess.Read<ValueTypeInfoData>(typeInfo.m_InfoData);

            Name = $"{remoteProcess.ReadString(typeInfoData.m_Name, 255)}";
            ThisTypeInfo = address;
            Type = typeInfoData.GetEntryType();
            Flags = typeInfoData.m_Flags;
            Alignment = typeInfoData.m_Alignment;
            TotalSize = typeInfoData.m_TotalSize;
            FieldCount = typeInfoData.m_FieldCount;
            RuntimeId = typeInfo.m_RuntimeId;
            Next = typeInfo.m_Next;

            // fill fields list
            if (FieldCount == 0)
            {
                SDKFieldEntry fieldEntry;

                fieldEntry.fieldType = "char";
                fieldEntry.fieldInternalType = "Uint8";
                fieldEntry.fieldBasicType = BasicTypesEnum.kTypeCode_Uint8;
                fieldEntry.fieldName = $"_0x000[{TotalSize}]";
                fieldEntry.fieldOffset = 0;
                fieldEntry.fieldSize = TotalSize;
                fieldEntry.lastFieldOffset = 0;
                fieldEntry.lastFieldSize = 0;

                Fields.Add(fieldEntry);

                FieldCount++;
            }
            else
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

                    fieldEntry.fieldInternalType = fieldTypeInfo.Name;
                    fieldEntry.fieldBasicType = fieldTypeInfo.Type;//fieldInfoData.GetEntryType();

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

                // the field array isn't always sorted in offset order so fix that
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
                            fieldEntry.fieldInternalType = "Uint8";
                            fieldEntry.fieldBasicType = BasicTypesEnum.kTypeCode_Uint8;
                            fieldEntry.fieldName = $"_0x{(Fields.ElementAt(i).fieldOffset + Fields.ElementAt(i).fieldSize).ToString("X4")}[{TotalSize - (Fields.ElementAt(i).fieldOffset + Fields.ElementAt(i).fieldSize)}]";
                            fieldEntry.fieldOffset = Fields.ElementAt(i).fieldOffset + Fields.ElementAt(i).fieldSize;
                            fieldEntry.fieldSize = TotalSize - (Fields.ElementAt(i).fieldOffset + Fields.ElementAt(i).fieldSize);
                            fieldEntry.lastFieldOffset = Fields.ElementAt(i).fieldOffset;
                            fieldEntry.lastFieldSize = Fields.ElementAt(i).fieldSize;

                            Fields.Add(fieldEntry);

                            FieldCount++;
                        }
                    }
                    else
                    {
                        // inter-field pads. seems to be correct now :)
                        if (Fields.ElementAt(i).fieldOffset > (Fields.ElementAt(i).lastFieldOffset + Fields.ElementAt(i).lastFieldSize))
                        {
                            fieldEntry.fieldType = "char";
                            fieldEntry.fieldInternalType = "Uint8";
                            fieldEntry.fieldBasicType = BasicTypesEnum.kTypeCode_Uint8;
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
        }
    }
}