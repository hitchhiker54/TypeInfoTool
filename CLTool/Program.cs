using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SWBF2Tool
{
    class Program
    {
        private static RemoteProcess remoteProcess = new RemoteProcess("starwarsbattlefrontii");
        private static List<SDKEnumFieldInfo> enumList = new List<SDKEnumFieldInfo>();
        private static List<SDKValueTypeInfo> structList = new List<SDKValueTypeInfo>();
        private static List<SDKClassInfo> classList = new List<SDKClassInfo>();

        private static void ProcessEnumType(IntPtr next)
        {
            enumList.Add(new SDKEnumFieldInfo(next, remoteProcess));
        }

        private static void ProcessValueType(IntPtr next)
        {
            structList.Add(new SDKValueTypeInfo(next, remoteProcess));
        }

        static void Main(string[] args)
        {
            //remoteProcess = new RemoteProcess("starwarsbattlefrontii");
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
                if (typeInfo.Name.Contains("Float32"))
                {
                    // uneeded class
                    type = BasicTypesEnum.kTypeCode_Void;
                }

                switch (type)
                {
                    case BasicTypesEnum.kTypeCode_Enum:
                        {
                            ProcessEnumType(next);
                        }
                        break;
                    case BasicTypesEnum.kTypeCode_ValueType:
                        {
                            ProcessValueType(next);
                        }
                        break;
                    case BasicTypesEnum.kTypeCode_Class:
                        {
                            //classList.Add(new SDKClassInfo(next, remoteProcess, peImageBuffer));


                            if (tasksCount == Environment.ProcessorCount)
                            {
                                Task.WaitAll(tasks.ToArray());
                                tasksCount = 0;
                            }

                            // experimental multitasking of the classes to speed up finding vtables
                            thisNext = next;

                            tasks.Add(
                                Task.Run(() =>
                                {
                                    var cInfo = new SDKClassInfo(thisNext, remoteProcess, peImageBuffer);
                                    classList.Add(cInfo);
                                }
                                ));

                            ++tasksCount;
                        }
                        break;
                    default:
                        break;
                }

                next = typeInfo.Next;

                count++;
            }

            Task.WaitAll(tasks.ToArray());

            var enumLines = new List<string>();
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
                    enumLines.Add($"    {enumInfo.Fields.ElementAt(i).fieldName}{end} //0x{i.ToString("X4")}");
                }

                enumLines.Add("};");
                enumLines.Add("");
            }

            var structLines = new List<string>();
            foreach (SDKValueTypeInfo structInfo in structList)
            {
                structLines.Add("////////////////////////////////////////");
                structLines.Add($"// Runtime Id : {structInfo.RuntimeId}");
                structLines.Add($"// TypeInfo : 0x{structInfo.ThisTypeInfo.ToString("X9")}");

                structLines.Add($"struct {structInfo.Name}");

                structLines.Add("{");

                for (int i = 0; i < structInfo.FieldCount; i++)
                {
                    structLines.Add($"    {structInfo.Fields.ElementAt(i).fieldType} {structInfo.Fields.ElementAt(i).fieldName}; //0x{structInfo.Fields.ElementAt(i).fieldOffset.ToString("X4")}");
                }

                structLines.Add("};");
                structLines.Add("");
            }

            var nameLines = new List<string>
            {
                "from idautils import *",
                "from idc import *",
                "from idaapi import *",
                "",
                "def MakeNames():",
                "    startEa = SegByBase(SegByName(\"HEADER\"))",
                "    imageend = 0",
                "",
                "    for ea in Segments():",
                "        imageend = SegEnd(ea)",
                ""
            };
            var classLines = new List<string>();
            foreach (SDKClassInfo classInfo in classList)
            {
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
                    classLines.Add($"    {classInfo.Fields.ElementAt(i).fieldType} {classInfo.Fields.ElementAt(i).fieldName}; //0x{classInfo.Fields.ElementAt(i).fieldOffset.ToString("X4")}");
                }

                classLines.Add("};");
                classLines.Add($"//0x{classInfo.TotalSize.ToString("X4")}");

                classLines.Add($"#endif");

                classLines.Add("");

                // idapython stuff
                if (classInfo.GetTypeFunction != IntPtr.Zero)
                {
                    nameLines.Add($"    MakeName(0x{classInfo.GetTypeFunction.ToString("X9")}, \"{classInfo.Name}_GetType\")");
                }

                if (classInfo.VTable != IntPtr.Zero)
                {
                    nameLines.Add($"    MakeName(0x{classInfo.VTable.ToString("X9")}, \"{classInfo.Name}_vtbl\")");
                }
            }

            //// buffers for the main .h files
            //var enumLines = new List<string>();
            //var structLines = new List<string>();
            //var classLines = new List<string>();

            //// buffer for the idapython script
            //var nameLines = new List<string>
            //{
            //    "from idautils import *",
            //    "from idc import *",
            //    "from idaapi import *",
            //    "",
            //    "def MakeNames():",
            //    "    startEa = SegByBase(SegByName(\"HEADER\"))",
            //    "    imageend = 0",
            //    "",
            //    "    for ea in Segments():",
            //    "        imageend = SegEnd(ea)",
            //    ""
            //};

            //// buffers for sorting by dependency
            //var structList = new List<SDKValueTypeInfo>();
            //var classList = new List<SDKValueTypeInfo>();

            //while (remoteProcess.IsValidImagePtr(next))
            //{
            //    SDKTypeInfo typeInfo = new SDKTypeInfo(next, remoteProcess);

            //    var type = typeInfo.Type;
            //    if (typeInfo.Name.Contains('('))
            //    {
            //        // some functions apparently defined, skip for now
            //        type = BasicTypesEnum.kTypeCode_Void;
            //    }

            //    if (type == BasicTypesEnum.kTypeCode_Enum)
            //    {
            //        var enumInfo = new SDKEnumFieldInfo(next, remoteProcess);

            //        enumLines.Add("////////////////////////////////////////");
            //        enumLines.Add($"// Runtime Id : {enumInfo.RuntimeId}");
            //        enumLines.Add($"// TypeInfo : 0x{enumInfo.ThisTypeInfo.ToString("X9")}");

            //        enumLines.Add($"enum {enumInfo.Name}");

            //        enumLines.Add("{");

            //        for (int i = 0; i < enumInfo.FieldCount; i++)
            //        {
            //            string end = ",";
            //            if (i == enumInfo.FieldCount - 1)
            //            {
            //                end = "";
            //            }
            //            enumLines.Add($"    {enumInfo.Fields.ElementAt(i).fieldName}{end} //0x{i.ToString("X4")}");
            //        }

            //        enumLines.Add("};");
            //        enumLines.Add("");
            //    }

            //    if (type == BasicTypesEnum.kTypeCode_ValueType)
            //    {
            //        var structInfo = new SDKValueTypeInfo(next, remoteProcess);

            //        structLines.Add("////////////////////////////////////////");
            //        structLines.Add($"// Runtime Id : {structInfo.RuntimeId}");
            //        structLines.Add($"// TypeInfo : 0x{structInfo.ThisTypeInfo.ToString("X9")}");

            //        structLines.Add($"struct {structInfo.Name}");

            //        structLines.Add("{");

            //        for (int i = 0; i < structInfo.FieldCount; i++)
            //        {
            //            structLines.Add($"    {structInfo.Fields.ElementAt(i).fieldType} {structInfo.Fields.ElementAt(i).fieldName}; //0x{structInfo.Fields.ElementAt(i).fieldOffset.ToString("X4")}");
            //        }

            //        structLines.Add("};");
            //        structLines.Add("");
            //    }

            //    if (type == BasicTypesEnum.kTypeCode_Class)
            //    {
            //        var classInfo = new SDKClassInfo(next, remoteProcess, peImageBuffer);


            //        classLines.Add("////////////////////////////////////////");
            //        classLines.Add($"// Class Id : {classInfo.ClassId}");
            //        classLines.Add($"// Runtime Id : {classInfo.RuntimeId}");
            //        classLines.Add($"// TypeInfo : 0x{classInfo.ThisTypeInfo.ToString("X9")}");
            //        classLines.Add($"// Default Instance : 0x{classInfo.DefaultInstance.ToString("X9")}");
            //        classLines.Add($"// Vtable : 0x{classInfo.VTable.ToString("X9")}");

            //        classLines.Add($"#ifndef _{classInfo.Name}_");
            //        classLines.Add($"#define _{classInfo.Name}_");

            //        if ((classInfo.ParentClassName != classInfo.Name) && (classInfo.ParentClassName != ""))
            //        {
            //            classLines.Add($"class {classInfo.Name} : {classInfo.ParentClassName}");
            //        }
            //        else
            //        {
            //            classLines.Add($"class {classInfo.Name}");
            //        }

            //        classLines.Add("{");

            //        if (classInfo.FieldCount > 0)
            //        {
            //            classLines.Add("public:");
            //        }

            //        for (int i = 0; i < classInfo.FieldCount; i++)
            //        {
            //            classLines.Add($"    {classInfo.Fields.ElementAt(i).fieldType} {classInfo.Fields.ElementAt(i).fieldName}; //0x{classInfo.Fields.ElementAt(i).fieldOffset.ToString("X4")}");
            //        }

            //        classLines.Add("};");
            //        classLines.Add($"//0x{classInfo.TotalSize.ToString("X4")}");

            //        classLines.Add($"#endif");

            //        classLines.Add("");

            //        // idapython stuff
            //        if(classInfo.GetTypeFunction != IntPtr.Zero)
            //        {
            //            nameLines.Add($"    MakeName(0x{classInfo.GetTypeFunction.ToString("X9")}, \"{classInfo.Name}_GetType\")");
            //        }

            //        if (classInfo.VTable != IntPtr.Zero)
            //        {
            //            nameLines.Add($"    MakeName(0x{classInfo.VTable.ToString("X9")}, \"{classInfo.Name}_vtbl\")");
            //        }
            //    }

            //    next = typeInfo.Next;

            //    count++;
            //}

            System.IO.File.WriteAllLines(@".\Enums.h", enumLines);
            System.IO.File.WriteAllLines(@".\Structs.h", structLines);
            System.IO.File.WriteAllLines(@".\Classes.h", classLines);
            System.IO.File.WriteAllLines(@".\MakeNames.py", nameLines);

            Console.WriteLine($"Found {count} TypeInfo entries.");

            Console.WriteLine("Done. Press a key to quit.");

            remoteProcess.CloseProcessMemory();

            Console.ReadLine();
        }
    }
}
