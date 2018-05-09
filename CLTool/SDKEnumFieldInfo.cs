using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

/*
 * Error D:\dump\swbf2\26-4-18 update\Enums.h,10051: Type 'CutsceneActorType' is already defined
Error D:\dump\swbf2\26-4-18 update\Enums.h,13101: Type 'DSJetpackMovementMode' is already defined
Error D:\dump\swbf2\26-4-18 update\Enums.h,13835: Type 'AIPathLinkDirection' is already defined
 * */

namespace SWBF2Tool
{
    public class SDKEnumFieldInfo : SDKTypeInfo
    {
        public List<SDKFieldEntry> Fields { get; protected set; } = new List<SDKFieldEntry>();

        public SDKEnumFieldInfo() : base()
        {
            
        }

        public SDKEnumFieldInfo(IntPtr address, RemoteProcess remoteProcess)
        {
            EnumFieldInfo typeInfo = remoteProcess.Read<EnumFieldInfo>(address);
            EnumFieldInfoData typeInfoData = remoteProcess.Read<EnumFieldInfoData>(typeInfo.m_InfoData);

            Name = $"{remoteProcess.ReadString(typeInfoData.m_Name, 255)}";
            ThisTypeInfo = address;
            Type = typeInfoData.GetEntryType();
            Flags = typeInfoData.m_Flags;
            Alignment = typeInfoData.m_Alignment;
            TotalSize = typeInfoData.m_TotalSize;
            FieldCount = typeInfoData.m_FieldCount;
            RuntimeId = typeInfo.m_RuntimeId;
            Next = typeInfo.m_Next;

            if (FieldCount > 0)
            {
                for (int i = 0; i < FieldCount; i++)
                {
                    var fieldInfoData = remoteProcess.Read<FieldInfoData>((IntPtr)((Int64)typeInfoData.m_Fields + (i * 0x18)));

                    SDKFieldEntry fieldEntry;

                    fieldEntry.fieldName = remoteProcess.ReadString(fieldInfoData.m_Name, 255);
                    fieldEntry.fieldType = "";
                    fieldEntry.fieldInternalType = "";
                    fieldEntry.fieldBasicType = BasicTypesEnum.kTypeCode_Void;
                    fieldEntry.fieldOffset = 0;
                    fieldEntry.fieldSize = 0;
                    fieldEntry.lastFieldOffset = 0;
                    fieldEntry.lastFieldSize = 0;

                    Fields.Add(fieldEntry);
                }
            }
        }
    }
}
