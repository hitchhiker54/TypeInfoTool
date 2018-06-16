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
    class Program
    {
        private static string FixTypeName(string name)
        {
            switch (name)
            {
                case "Int8":
                    name = "int8_t";
                    break;
                case "Uint8":
                    name = "uint8_t";
                    break;
                case "Int16":
                    name = "int16_t";
                    break;
                case "Uint16":
                    name = "uint16_t";
                    break;
                case "Int32":
                    name = "int32_t";
                    break;
                case "Uint32":
                    name = "uint32_t";
                    break;
                case "Int64":
                    name = "int64_t";
                    break;
                case "Uint64":
                    name = "uint64_t";
                    break;
                case "Float32":
                    name = "float";
                    break;
                case "Float64":
                    name = "double";
                    break;
                case "Boolean":
                    name = "int16_t";
                    break;
                case "CString":
                    {
                        //if (Type == BasicTypesEnum.kTypeCode_Class)
                        //{
                        //    name = "char*";
                        //}
                        //else
                        //{
                        //    name = "char";
                        //}
                        name = "char*";
                    }
                    break;
                default:
                    {
                        //if ((Type == BasicTypesEnum.kTypeCode_Class) || (Type == BasicTypesEnum.kTypeCode_Array))
                        //{
                        //    name = $"fb::{name}*";
                        //}
                        //if ((Type == BasicTypesEnum.kTypeCode_ValueType) || (Type == BasicTypesEnum.kTypeCode_Enum))
                        //{
                        //    name = $"fb::{name}";
                        //}
                    }
                    break;
            }

            return name;
        }

        static void Main(string[] args)
        {
            RemoteProcess remoteProcess = new RemoteProcess("starwarsbattlefrontii");

            List<SDKEnumFieldInfo> enumList = new List<SDKEnumFieldInfo>();
            List<SDKValueTypeInfo> structList = new List<SDKValueTypeInfo>();
            List<SDKClassInfo> classList = new List<SDKClassInfo>();

            //bool forIDA = false;    // set true to adjust output for IDA import (Array<> becomes pointer to type)

            remoteProcess.OpenProcessMemory();

            var peImageBuffer = new PEImageBuffer(remoteProcess);

            var firstTypeInfoPtr = peImageBuffer.FindOffset("48 8B 05 ? ? ? ? 48 89 41 08 48 89 0D ? ? ? ?");
            var firstTypeInfo = remoteProcess.Read<IntPtr>((IntPtr)firstTypeInfoPtr);

            Console.WriteLine($"Image Base : 0x{remoteProcess.ImageBase.ToString("X9")}");
            Console.WriteLine($"Image Size : 0x{remoteProcess.ImageSize.ToString("X9")}");
            Console.WriteLine("");
            Console.WriteLine($"OFFSET_FirstTypeInfo : 0x{firstTypeInfoPtr.ToString("X9")}");

            var next = firstTypeInfo;

            Console.WriteLine("Processing...");
            var count = 1;

            // testing in reclass
            var classcount = 1;
            var structcount = 1;
            var enumcount = 1;

            var tasks = new List<Task>();
            var tasksCount = 0;
            var thisNext = next;

            while (remoteProcess.IsValidImagePtr(next))
            {
                var typeInfo = new SDKTypeInfo(next, remoteProcess);

                var type = typeInfo.Type;
                if (typeInfo.Name.Contains('('))
                {
                    // some functions apparently defined, skip for now investigate later
                    type = BasicTypesEnum.kTypeCode_Void;
                }
                if ((typeInfo.Name.Contains("Float32")) || (typeInfo.Name.Contains("char")))
                {
                    // uneeded class
                    type = BasicTypesEnum.kTypeCode_Void;
                }

                switch (type)
                {
                    case BasicTypesEnum.kTypeCode_Enum:
                        {
                            enumList.Add(new SDKEnumFieldInfo(next, remoteProcess));
                            ++enumcount;
                        }
                        break;
                    case BasicTypesEnum.kTypeCode_ValueType:
                        {
                            structList.Add(new SDKValueTypeInfo(next, remoteProcess));
                            ++structcount;
                        }
                        break;
                    case BasicTypesEnum.kTypeCode_Class:
                        {
                            classList.Add(new SDKClassInfo(next, remoteProcess, peImageBuffer));


                            //if (tasksCount == Environment.ProcessorCount)
                            //{
                            //    Task.WaitAll(tasks.ToArray());
                            //    tasksCount = 0;
                            //}

                            //// experimental multitasking of the classes to speed up finding vtables
                            //thisNext = next;

                            //tasks.Add(
                            //    Task.Run(() =>
                            //    {
                            //        var cInfo = new SDKClassInfo(thisNext, remoteProcess, peImageBuffer);
                            //        classList.Add(cInfo);
                            //    }
                            //    ));

                            //++tasksCount;

                            ++classcount;
                        }
                        break;
                    case BasicTypesEnum.kTypeCode_BasicTypeCount:
                        {
                            Console.WriteLine($"{typeInfo.Name}");
                        }
                        break;
                    default:
                        break;
                }

                next = typeInfo.Next;

                ++count;
            }

            Task.WaitAll(tasks.ToArray());

            ProcessHeaders.CreateHeaders(ref enumList, ref structList, ref classList);

//            var enumLines = new List<string>();

//            if (!forIDA)
//            {
//                enumLines.Add("#pragma once");
//                enumLines.Add("");
//                enumLines.Add("namespace fb");
//                enumLines.Add("{");
//            }

//            foreach (SDKEnumFieldInfo enumInfo in enumList)
//            {
//                enumLines.Add("////////////////////////////////////////");
//                enumLines.Add($"// Runtime Id : {enumInfo.RuntimeId}");
//                enumLines.Add($"// TypeInfo : 0x{enumInfo.ThisTypeInfo.ToString("X9")}");

//                enumLines.Add($"enum {enumInfo.Name}");

//                enumLines.Add("{");

//                for (int i = 0; i < enumInfo.FieldCount; i++)
//                {
//                    string end = ",";
//                    if (i == enumInfo.FieldCount - 1)
//                    {
//                        end = "";
//                    }

//                    // fix some small issues related to having all the enums in the same file
//                    var fieldName = enumInfo.Fields.ElementAt(i).fieldName;
//                    if ((enumInfo.Name == "CutsceneActorType") || (enumInfo.Name == "DSJetpackMovementMode") || (enumInfo.Name == "AIPathLinkDirection"))
//                    {
//                        fieldName = $"{fieldName}_";
//                    }

//                    enumLines.Add($"    {fieldName}{end} //0x{i.ToString("X4")}");
//                }

//                enumLines.Add("};");
//                enumLines.Add("");
//            }

//            if (!forIDA)
//            {
//                enumLines.Add("}");
//            }

//            // sort structs for dependencies
//            int infoCount = 0;
//            while (infoCount < structList.Count)
//            {
//                var item = structList.ElementAt(infoCount);

//                foreach (SDKFieldEntry field in item.Fields)
//                {
//                    var fieldIndex = 0;
//                    var fieldTypeName = field.fieldType;

//                    if (fieldTypeName.Contains("-Array"))
//                    {
//                        fieldTypeName = field.fieldType.Substring(0, field.fieldType.Length - 6);
//                    }

//                    if ((field.fieldBasicType == BasicTypesEnum.kTypeCode_ValueType)
//                        || (field.fieldBasicType == BasicTypesEnum.kTypeCode_Array))
//                    {
//                        foreach (SDKValueTypeInfo fieldInfo in structList)
//                        {
//                            if (fieldInfo.Name == fieldTypeName)
//                            {
//                                fieldIndex = structList.IndexOf(fieldInfo);
//                            }
//                        }

//                        if (fieldIndex != 0)
//                        {
//                            var itemIndex = structList.IndexOf(item);

//                            // if we find the field item lower than the owning type, drop the owning type below it
//                            if (fieldIndex > itemIndex)
//                            {
//                                var tempInfo = structList.ElementAt(itemIndex);
//                                structList.RemoveAt(itemIndex);
//                                structList.Insert(fieldIndex, tempInfo);

//                                // start the list again
//                                infoCount = 0;
//                                break;
//                            }
//                        }
//                    }
//                }

//                ++infoCount;
//            }

//            var structLines = new List<string>();

//            if (!forIDA)
//            {
//                structLines.Add("#pragma once");
//                structLines.Add("");
//                structLines.Add("namespace fb");
//                structLines.Add("{");
//            }

//            foreach (SDKValueTypeInfo structInfo in structList)
//            {
//                structLines.Add("////////////////////////////////////////");
//                structLines.Add($"// Runtime Id : {structInfo.RuntimeId}");
//                structLines.Add($"// TypeInfo : 0x{structInfo.ThisTypeInfo.ToString("X9")}");

//                structLines.Add($"struct {structInfo.Name}");

//                structLines.Add("{");

//                for (int i = 0; i < structInfo.FieldCount; i++)
//                {
//                    var fieldType = structInfo.Fields.ElementAt(i).fieldType;
//                    var postfix = "";

//                    if (fieldType.Contains("-Array"))
//                    {
//                        fieldType = fieldType.Substring(0, fieldType.Length - 6);
//                    }

//                    fieldType = FixTypeName(fieldType);

//                    if ((structInfo.Fields.ElementAt(i).fieldBasicType == BasicTypesEnum.kTypeCode_Class) && (fieldType != "float"))
//                    {
//                        postfix = "*";
//                    }

//                    if (structInfo.Fields.ElementAt(i).fieldBasicType == BasicTypesEnum.kTypeCode_Array)
//                    {
//                        if (forIDA)
//                        {
//                            postfix = "*";
//                        }
//                        else
//                        {
//                            fieldType = $"Array<{fieldType}>";
//                        }
//                    }

//                    structLines.Add($"    {fieldType}{postfix} {structInfo.Fields.ElementAt(i).fieldName}; //0x{structInfo.Fields.ElementAt(i).fieldOffset.ToString("X4")}");
//                }

//                structLines.Add("};");
//                structLines.Add("");
//            }

//            if (!forIDA)
//            {
//                structLines.Add("}");
//            }

//            // sort by classid
//            classList = classList.OrderBy(x => x.ClassId).ToList();

//            var nameLines = new List<string>
//            {
//                "from idautils import *",
//                "from idc import *",
//                "from idaapi import *",
//                "",
//                "def MakeNames():",
//                "    startEa = SegByBase(SegByName(\"HEADER\"))",
//                "    imageend = 0",
//                "",
//                "    for ea in Segments():",
//                "        imageend = SegEnd(ea)",
//                ""
//            };
//            var classLines = new List<string>();

//            if (!forIDA)
//            {
//                classLines.Add("#pragma once");
//                classLines.Add("");
//                classLines.Add("namespace fb");
//                classLines.Add("{");
//            }

//            var declarationLines = new List<string>();

//            if (!forIDA)
//            {
//                declarationLines.Add("#pragma once");
//                declarationLines.Add("");
//                declarationLines.Add("namespace fb");
//                declarationLines.Add("{");
//            }

//            foreach (SDKClassInfo classInfo in classList)
//            {
//                classLines.Add("////////////////////////////////////////");
//                classLines.Add($"// Class Id : {classInfo.ClassId}");
//                classLines.Add($"// Runtime Id : {classInfo.RuntimeId}");
//                classLines.Add($"// TypeInfo : 0x{classInfo.ThisTypeInfo.ToString("X9")}");
//                classLines.Add($"// Default Instance : 0x{classInfo.DefaultInstance.ToString("X9")}");
//                classLines.Add($"// Vtable : 0x{classInfo.VTable.ToString("X9")}");

//                classLines.Add($"#ifndef _{classInfo.Name}_");
//                classLines.Add($"#define _{classInfo.Name}_");

//                if ((classInfo.ParentClassName != classInfo.Name) && (classInfo.ParentClassName != ""))
//                {
//                    classLines.Add($"class {classInfo.Name} : {classInfo.ParentClassName}");
//                }
//                else
//                {
//                    classLines.Add($"class {classInfo.Name}");
//                }

//                classLines.Add("{");

//                if (classInfo.FieldCount > 0)
//                {
//                    classLines.Add("public:");
//                }

//                for (int i = 0; i < classInfo.FieldCount; i++)
//                {
//                    var fieldType = classInfo.Fields.ElementAt(i).fieldType;
//                    var postfix = "";

//                    if (fieldType.Contains("-Array"))
//                    {
//                        fieldType = fieldType.Substring(0, fieldType.Length - 6);
//                    }

//                    fieldType = FixTypeName(fieldType);

//                    if ((classInfo.Fields.ElementAt(i).fieldBasicType == BasicTypesEnum.kTypeCode_Class) && (fieldType != "float"))
//                    {
//                        postfix = "*";
//                    }

//                    if (classInfo.Fields.ElementAt(i).fieldBasicType == BasicTypesEnum.kTypeCode_Array)
//                    {
//                        if (forIDA)
//                        {
//                            postfix = "*";
//                        }
//                        else
//                        {
//                            fieldType = $"Array<{fieldType}>";
//                        }
//                    }

//                    classLines.Add($"    {fieldType}{postfix} {classInfo.Fields.ElementAt(i).fieldName}; //0x{classInfo.Fields.ElementAt(i).fieldOffset.ToString("X4")}");
//                }

//                classLines.Add("};");
//                classLines.Add($"//0x{classInfo.TotalSize.ToString("X4")}");

//                classLines.Add($"#endif");

//                classLines.Add("");

//                declarationLines.Add($"class {classInfo.Name};");

//                // idapython stuff
//                /*
//                 * Python>MakeNames()
//14356C140: can't rename byte as 'PlayerAbilityWeaponInfoEntityData_vtbl' because this byte can't have a name (it is a tail byte).
//14356C178: can't rename byte as 'PlayerAbilityWeaponUpgradeInfoEntityData_vtbl' because this byte can't have a name (it is a tail byte).
//1413481DC: can't rename byte as 'ClientWheelComponent_vtbl' because this byte can't have a name (it is a tail byte).
//141948644: can't rename byte as 'ServerVehicleHealthComponent_vtbl' because this byte can't have a name (it is a tail byte).
//                 */
//                if (classInfo.GetTypeFunction != IntPtr.Zero)
//                {
//                    nameLines.Add($"    MakeName(0x{classInfo.GetTypeFunction.ToString("X9")}, \"{classInfo.Name}_GetType\")");
//                }

//                if (classInfo.VTable != IntPtr.Zero)
//                {
//                    nameLines.Add($"    MakeName(0x{classInfo.VTable.ToString("X9")}, \"{classInfo.Name}_vtbl\")");
//                }
//            }

//            if (!forIDA)
//            {
//                classLines.Add("}");
//            }

//            if (!forIDA)
//            {
//                declarationLines.Add("}");
//            }

//            System.IO.File.WriteAllLines(@".\Enums.h", enumLines);
//            System.IO.File.WriteAllLines(@".\Structs.h", structLines);
//            System.IO.File.WriteAllLines(@".\Declarations.h", declarationLines);
//            System.IO.File.WriteAllLines(@".\Classes.h", classLines);
//            System.IO.File.WriteAllLines(@".\MakeNames.py", nameLines);

//            // c++ import header
//            var cppImportLines = new List<string>
//            {
//                "#pragma once",
//                "",
//                "namespace fb {",
//                "    struct Guid",
//                "    {",
//                "        unsigned long	m_Data1;	//0x0000",
//                "        unsigned short	m_Data2;	//0x0004",
//                "        unsigned short	m_Data3;	//0x0006",
//                "        unsigned char	m_Data4[8];	//0x0008",
//                "    };",
//                "    //Size=0x0010",
//                "",
//                "    typedef __m128 BoxedValueRef;",
//                "    typedef uint64_t ResourceRef;",
//                "    typedef uint64_t TypeRef;",
//                "    typedef uint64_t FileRef;",
//                "",
//                "    typedef struct",
//                "    {",
//                "    	char pad[0x14];",
//                "    } SHA1;",
//                "    //Size=0x0014",
//                "",
//                "    template <typename T>",
//                "    class Array",
//                "    {",
//                "    private:",
//                "    	 T* m_firstElement;",
//                "",
//                "    public:",
//                "        T At(INT nIndex)",
//                "        {",
//                "            if (m_firstElement == NULL)",
//                "                return *(T*)((UINT64)NULL);",
//                "",
//                "            return *(T*)((UINT64)m_firstElement + (nIndex * sizeof(T)));",
//                "         };",
//                "",
//                "         T operator [](INT index) { return At(index); }",
//                "    };",
//                "",
//                "    #include \"Declarations.h\"",
//                "    #include \"Enums.h\"",
//                "    #include \"Structs.h\"",
//                "    #include \"Classes.h\"",
//                "",
//            };

//            // IDA import header
//            var idaImportLines = new List<string>
//            {
//                "from idautils import *",
//                "from idc import *",
//                "from idaapi import *",
//                "",
//                "def MakeNames():",
//                "    startEa = SegByBase(SegByName(\"HEADER\"))",
//                "    imageend = 0",
//                "",
//                "    for ea in Segments():",
//                "        imageend = SegEnd(ea)",
//                ""
//            };

            Console.WriteLine($"Found {count} TypeInfo entries.");
            Console.WriteLine($"Found {classcount} ClassInfo entries.");
            Console.WriteLine($"Found {structcount} ValueTypeInfo entries.");
            Console.WriteLine($"Found {enumcount} EnumFieldInfo entries.");

            Console.WriteLine("Done. Press a key to quit.");

            remoteProcess.CloseProcessMemory();

            Console.ReadLine();
        }
    }
}
