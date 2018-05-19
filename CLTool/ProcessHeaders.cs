using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SWBF2Tool
{
    public static class ProcessHeaders
    {
        public static void CreateHeaders(ref List<SDKEnumFieldInfo> enumList, ref List<SDKValueTypeInfo> structList, ref List<SDKClassInfo> classList)
        {
            // sort structs for dependencies
            int infoCount = 0;
            while (infoCount < structList.Count)
            {
                var item = structList.ElementAt(infoCount);

                foreach (SDKFieldEntry field in item.Fields)
                {
                    var fieldIndex = 0;
                    var fieldTypeName = field.fieldType;

                    if (fieldTypeName.Contains("-Array"))
                    {
                        fieldTypeName = field.fieldType.Substring(0, field.fieldType.Length - 6);
                    }

                    if ((field.fieldBasicType == BasicTypesEnum.kTypeCode_ValueType)
                        || (field.fieldBasicType == BasicTypesEnum.kTypeCode_Array))
                    {
                        foreach (SDKValueTypeInfo fieldInfo in structList)
                        {
                            if (fieldInfo.Name == fieldTypeName)
                            {
                                fieldIndex = structList.IndexOf(fieldInfo);
                            }
                        }

                        if (fieldIndex != 0)
                        {
                            var itemIndex = structList.IndexOf(item);

                            // if we find the field item lower than the owning type, drop the owning type below it
                            if (fieldIndex > itemIndex)
                            {
                                var tempInfo = structList.ElementAt(itemIndex);
                                structList.RemoveAt(itemIndex);
                                structList.Insert(fieldIndex, tempInfo);

                                // start the list again
                                infoCount = 0;
                                break;
                            }
                        }
                    }
                }

                ++infoCount;
            }

            // sort by classid
            classList = classList.OrderBy(x => x.ClassId).ToList();

            CreateCppHeaders(ref enumList, ref structList, ref classList);
            CreateIDAHeaders(ref enumList, ref structList, ref classList);
        }

        public static void CreateCppHeaders(ref List<SDKEnumFieldInfo> enumList, ref List<SDKValueTypeInfo> structList, ref List<SDKClassInfo> classList)
        {
            var enumLines = new List<string>();
            var structLines = new List<string>();
            var classLines = new List<string>();
            var declarationLines = new List<string>();

            System.IO.Directory.CreateDirectory(@".\cpp");

            enumLines.Add("#pragma once");
            enumLines.Add("");
            enumLines.Add("namespace fb");
            enumLines.Add("{");

            foreach (SDKEnumFieldInfo enumInfo in enumList)
            {
                enumLines.Add("////////////////////////////////////////");
                enumLines.Add($"// Runtime Id : {enumInfo.RuntimeId}");
                enumLines.Add($"// TypeInfo : 0x{enumInfo.ThisTypeInfo.ToString("X9")}");

                enumLines.Add($"enum {enumInfo.Name}");

                enumLines.Add("{");

                for (int i = 0; i < enumInfo.FieldCount; i++)
                {
                    string end = ",";
                    if (i == enumInfo.FieldCount - 1)
                    {
                        end = "";
                    }

                    // fix some small issues related to having all the enums in the same file
                    var fieldName = enumInfo.Fields.ElementAt(i).fieldName;
                    if ((enumInfo.Name == "CutsceneActorType") || (enumInfo.Name == "DSJetpackMovementMode") || (enumInfo.Name == "AIPathLinkDirection"))
                    {
                        fieldName = $"{fieldName}_";
                    }

                    enumLines.Add($"    {fieldName}{end} //0x{i.ToString("X4")}");
                }

                enumLines.Add("};");
                enumLines.Add("");
            }

            enumLines.Add("}");

            structLines.Add("#pragma once");
            structLines.Add("");
            structLines.Add("namespace fb");
            structLines.Add("{");

            foreach (SDKValueTypeInfo structInfo in structList)
            {
                structLines.Add("////////////////////////////////////////");
                structLines.Add($"// Runtime Id : {structInfo.RuntimeId}");
                structLines.Add($"// TypeInfo : 0x{structInfo.ThisTypeInfo.ToString("X9")}");

                structLines.Add($"struct {structInfo.Name}");

                structLines.Add("{");

                for (int i = 0; i < structInfo.FieldCount; i++)
                {
                    var fieldType = structInfo.Fields.ElementAt(i).fieldType;
                    var postfix = "";
                    var prefix = "";

                    if (fieldType.Contains("-Array"))
                    {
                        fieldType = fieldType.Substring(0, fieldType.Length - 6);
                    }

                    fieldType = FixTypeName(fieldType);

                    if ((structInfo.Fields.ElementAt(i).fieldBasicType == BasicTypesEnum.kTypeCode_Enum) ||
                                (structInfo.Fields.ElementAt(i).fieldBasicType == BasicTypesEnum.kTypeCode_ValueType) && (fieldType != "uint64_t"))
                    {
                        prefix = "fb::";
                    }

                    if ((structInfo.Fields.ElementAt(i).fieldBasicType == BasicTypesEnum.kTypeCode_Class) && (fieldType != "float"))
                    {
                        prefix = "fb::";
                        postfix = "*";
                    }

                    if (structInfo.Fields.ElementAt(i).fieldBasicType == BasicTypesEnum.kTypeCode_Array)
                    {
                        var fieldPrefix = "";
                        var fieldPostfix = "";

                        foreach(SDKClassInfo c in classList)
                        {
                            if (c.Name == fieldType)
                            {
                                fieldPrefix = "fb::";
                                fieldPostfix = "*";
                                break;
                            }
                        }

                        fieldType = $"Array<{fieldPrefix}{fieldType}{fieldPostfix}>";
                    }

                    structLines.Add($"    {prefix}{fieldType}{postfix} {structInfo.Fields.ElementAt(i).fieldName}; //0x{structInfo.Fields.ElementAt(i).fieldOffset.ToString("X4")}");
                }

                structLines.Add("};");
                structLines.Add("");
            }

            structLines.Add("}");

            classLines.Add("#pragma once");
            classLines.Add("");
            classLines.Add("namespace fb");
            classLines.Add("{");

            declarationLines.Add("#pragma once");
            declarationLines.Add("");
            declarationLines.Add("namespace fb");
            declarationLines.Add("{");

            foreach (SDKClassInfo classInfo in classList)
            {
                //classLines.Add("#pragma once");
                //classLines.Add("");
                //classLines.Add("namespace fb");
                //classLines.Add("{");

                if (classInfo.Name.Contains("::"))
                {
                    continue;
                }

                classLines.Add("////////////////////////////////////////");
                classLines.Add($"// Class Id : {classInfo.ClassId}");
                classLines.Add($"// Runtime Id : {classInfo.RuntimeId}");
                classLines.Add($"// TypeInfo : 0x{classInfo.ThisTypeInfo.ToString("X9")}");
                classLines.Add($"// Default Instance : 0x{classInfo.DefaultInstance.ToString("X9")}");
                classLines.Add($"// Vtable : 0x{classInfo.VTable.ToString("X9")}");

                classLines.Add($"#ifndef _{classInfo.Name}_");
                classLines.Add($"#define _{classInfo.Name}_");

                if ((classInfo.ParentClassName != classInfo.Name) && (classInfo.ParentClassName != ""))
                {
                    classLines.Add($"class {classInfo.Name} : public {classInfo.ParentClassName}");
                }
                else
                {
                    classLines.Add($"class {classInfo.Name}");
                }

                classLines.Add("{");

                if (classInfo.FieldCount > 0)
                {
                    classLines.Add("public:");
                }

                for (int i = 0; i < classInfo.FieldCount; i++)
                {
                    var fieldType = classInfo.Fields.ElementAt(i).fieldType;
                    var postfix = "";
                    var prefix = "";

                    if (fieldType.Contains("-Array"))
                    {
                        fieldType = fieldType.Substring(0, fieldType.Length - 6);
                    }

                    fieldType = FixTypeName(fieldType);

                    if ((classInfo.Fields.ElementAt(i).fieldBasicType == BasicTypesEnum.kTypeCode_Enum) || 
                                (classInfo.Fields.ElementAt(i).fieldBasicType == BasicTypesEnum.kTypeCode_ValueType) && (fieldType != "uint64_t"))
                    {
                        prefix = "fb::";
                    }

                    if ((classInfo.Fields.ElementAt(i).fieldBasicType == BasicTypesEnum.kTypeCode_Class) && (fieldType != "float"))
                    {
                        prefix = "fb::";
                        postfix = "*";
                    }

                    if (classInfo.Fields.ElementAt(i).fieldBasicType == BasicTypesEnum.kTypeCode_Array)
                    {
                        var fieldPostfix = "";
                        var fieldPrefix = "";

                        foreach (SDKClassInfo c in classList)
                        {
                            if (c.Name == fieldType)
                            {
                                fieldPrefix = "fb::";
                                fieldPostfix = "*";
                                break;
                            }
                        }

                        fieldType = $"Array<{fieldPrefix}{fieldType}{fieldPostfix}>";
                    }

                    classLines.Add($"    {prefix}{fieldType}{postfix} {classInfo.Fields.ElementAt(i).fieldName}; //0x{classInfo.Fields.ElementAt(i).fieldOffset.ToString("X4")}");
                }

                classLines.Add("};");
                classLines.Add($"//0x{classInfo.TotalSize.ToString("X4")}");

                classLines.Add($"#endif");

                //classLines.Add("}");

                classLines.Add("");

                declarationLines.Add($"class {classInfo.Name};");


                // handle name::name entires
                //var Name = classInfo.Name;

                //if (Name.Contains("::"))
                //{
                //    string[] parts = Name.Split(':');

                //    Name = $"{parts[0]}__{parts[2]}";
                //}

                //System.IO.File.WriteAllLines($".\\cpp\\{Name}.h", classLines);

                //classLines.Clear();
            }

            classLines.Add("}");
            declarationLines.Add("}");

            System.IO.File.WriteAllLines(@".\cpp\Enums.h", enumLines);
            System.IO.File.WriteAllLines(@".\cpp\Structs.h", structLines);
            System.IO.File.WriteAllLines(@".\cpp\Declarations.h", declarationLines);
            System.IO.File.WriteAllLines(@".\cpp\Classes.h", classLines);
        }

        public static void CreateIDAHeaders(ref List<SDKEnumFieldInfo> enumList, ref List<SDKValueTypeInfo> structList, ref List<SDKClassInfo> classList)
        {
            var enumLines = new List<string>();
            var structLines = new List<string>();
            var classLines = new List<string>();
            var declarationLines = new List<string>();
            var classIncludeLines = new List<string>();
            var allClassLines = new List<string>();

            System.IO.Directory.CreateDirectory(@".\ida");
            System.IO.Directory.CreateDirectory(@".\ida\singleclasses");

            foreach (SDKEnumFieldInfo enumInfo in enumList)
            {
                enumLines.Add("////////////////////////////////////////");
                enumLines.Add($"// Runtime Id : {enumInfo.RuntimeId}");
                enumLines.Add($"// TypeInfo : 0x{enumInfo.ThisTypeInfo.ToString("X9")}");

                enumLines.Add($"enum {enumInfo.Name}");

                enumLines.Add("{");

                for (int i = 0; i < enumInfo.FieldCount; i++)
                {
                    string end = ",";
                    if (i == enumInfo.FieldCount - 1)
                    {
                        end = "";
                    }

                    // fix some small issues related to having all the enums in the same file
                    var fieldName = enumInfo.Fields.ElementAt(i).fieldName;
                    if ((enumInfo.Name == "CutsceneActorType") || (enumInfo.Name == "DSJetpackMovementMode") || (enumInfo.Name == "AIPathLinkDirection"))
                    {
                        fieldName = $"{fieldName}_";
                    }

                    enumLines.Add($"    {fieldName}{end} //0x{i.ToString("X4")}");
                }

                enumLines.Add("};");
                enumLines.Add("");
            }

            foreach (SDKValueTypeInfo structInfo in structList)
            {
                structLines.Add("////////////////////////////////////////");
                structLines.Add($"// Runtime Id : {structInfo.RuntimeId}");
                structLines.Add($"// TypeInfo : 0x{structInfo.ThisTypeInfo.ToString("X9")}");

                structLines.Add($"struct {structInfo.Name}");

                structLines.Add("{");

                for (int i = 0; i < structInfo.FieldCount; i++)
                {
                    var fieldType = structInfo.Fields.ElementAt(i).fieldType;
                    var postfix = "";

                    if (fieldType.Contains("-Array"))
                    {
                        fieldType = fieldType.Substring(0, fieldType.Length - 6);
                    }

                    fieldType = FixTypeName(fieldType);

                    if ((structInfo.Fields.ElementAt(i).fieldBasicType == BasicTypesEnum.kTypeCode_Class) && (fieldType != "float"))
                    {
                        postfix = "*";
                    }

                    if (structInfo.Fields.ElementAt(i).fieldBasicType == BasicTypesEnum.kTypeCode_Array)
                    {
                        postfix = "*";
                    }

                    structLines.Add($"    {fieldType}{postfix} {structInfo.Fields.ElementAt(i).fieldName}; //0x{structInfo.Fields.ElementAt(i).fieldOffset.ToString("X4")}");
                }

                structLines.Add("};");
                structLines.Add("");
            }

            foreach (SDKClassInfo classInfo in classList)
            {
                if ((classInfo.ParentClassName != classInfo.Name) && (classInfo.ParentClassName != ""))
                {
                    classLines.Add($"class {classInfo.Name} : {classInfo.ParentClassName}");
                }
                else
                {
                    classLines.Add($"class {classInfo.Name}");
                }

                classLines.Add("{");

                if (classInfo.FieldCount > 0)
                {
                    classLines.Add("public:");
                }

                for (int i = 0; i < classInfo.FieldCount; i++)
                {
                    var fieldType = classInfo.Fields.ElementAt(i).fieldType;
                    var postfix = "";

                    if (fieldType.Contains("-Array"))
                    {
                        fieldType = fieldType.Substring(0, fieldType.Length - 6);
                    }

                    fieldType = FixTypeName(fieldType);

                    if ((classInfo.Fields.ElementAt(i).fieldBasicType == BasicTypesEnum.kTypeCode_Class) && (fieldType != "float"))
                    {
                        postfix = "*";
                    }

                    if (classInfo.Fields.ElementAt(i).fieldBasicType == BasicTypesEnum.kTypeCode_Array)
                    {
                        postfix = "*";
                    }

                    classLines.Add($"    {fieldType}{postfix} {classInfo.Fields.ElementAt(i).fieldName}; //0x{classInfo.Fields.ElementAt(i).fieldOffset.ToString("X4")}");
                }

                classLines.Add("};");
                classLines.Add($"//0x{classInfo.TotalSize.ToString("X4")}");

                classLines.Add("");

                declarationLines.Add($"class {classInfo.Name};");
                classIncludeLines.Add($"#include \"singleclasses\\{classInfo.Name}.h\"");

                // handle name::name entires
                var Name = classInfo.Name;

                if (Name.Contains("::"))
                {
                    string[] parts = Name.Split(':');

                    Name = $"{parts[0]}__{parts[2]}";
                }

                System.IO.File.WriteAllLines($".\\ida\\singleclasses\\{Name}.h", classLines);

                foreach (string line in classLines)
                {
                    allClassLines.Add(line);
                }
                allClassLines.Add("");

                classLines.Clear();
            }

            //classLines.Add("}");
            //declarationLines.Add("}");

            System.IO.File.WriteAllLines(@".\ida\Enums.h", enumLines);
            System.IO.File.WriteAllLines(@".\ida\Structs.h", structLines);
            System.IO.File.WriteAllLines(@".\ida\Declarations.h", declarationLines);
            System.IO.File.WriteAllLines(@".\ida\IncludeClasses.h", classIncludeLines);
            System.IO.File.WriteAllLines(@".\ida\Classes.h", allClassLines);
        }

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
                        //    name = $"{name}*";
                        //}
                        //if ((Type == BasicTypesEnum.kTypeCode_ValueType) || (Type == BasicTypesEnum.kTypeCode_Enum))
                        //{
                        //    name = $"{name}";
                        //}
                    }
                    break;
            }

            return name;
        }
    }
}
