using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace SWBF2Tool
{
    /// <summary>
    /// structures for PE header 64 bit only
    /// </summary>
    #region header structs
    public struct IMAGE_DOS_HEADER
    {
        public ushort e_magic;
        public ushort e_cblp;
        public ushort e_cp;
        public ushort e_crlc;
        public ushort e_cparhdr;
        public ushort e_minalloc;
        public ushort e_maxalloc;
        public ushort e_ss;
        public ushort e_sp;
        public ushort e_csum;
        public ushort e_ip;
        public ushort e_cs;
        public ushort e_lfarlc;
        public ushort e_ovno;
        public ushort[] e_res;
        public ushort e_oemid;
        public ushort e_oeminfo;
        public ushort[] d_res2;
        public int e_lfanew;
    }

    public struct IMAGE_FILE_HEADER
    {
        public ushort Machine;
        public ushort NumberOfSections;
        public ulong TimeDateStamp;
        public ulong PointerToSymbolTable;
        public ulong NumberOfSymbols;
        public ushort SizeOfOptionalHeader;
        public ushort Characteristics;
    }

    public struct IMAGE_OPTIONAL_HEADER
    {
        public ushort Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public UInt64 ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public ushort Subsystem;
        public ushort DllCharacteristics;
        public UInt64 SizeOfStackReserve;
        public UInt64 SizeOfStackCommit;
        public UInt64 SizeOfHeapReserve;
        public UInt64 SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
        public IMAGE_DATA_DIRECTORY[] DataDirectory;
    }

    public struct IMAGE_DATA_DIRECTORY
    {
        public uint VirtualAddress;
        public uint Size;
    }

    public struct IMAGE_NT_HEADERS
    {
        public uint Signature;
        public IMAGE_FILE_HEADER FileHeader;
        public IMAGE_OPTIONAL_HEADER OptionalHeader;
    }
    #endregion

    /// <summary>
    /// class RemoteProcess
    /// 
    /// Handles information on a remote process and memory access to that process.
    /// </summary>
    public class RemoteProcess
    {
        private static Process process;
        private static IntPtr processMemoryHandle;

        public IntPtr ImageBase { get; private set; }
        public int ImageSize { get; private set; }
        public Process Process {
            get { return process; }
        }
        public IntPtr ProcessMemoryHandle {
            get { return processMemoryHandle; }
        }
        public bool ValidProcess { get; private set; }

        public RemoteProcess(string processName)
        {
            if (GetProcessesByName(processName))
            {
                ImageBase = process.MainModule.BaseAddress;
                ImageSize = process.MainModule.ModuleMemorySize;
                ValidProcess = true;
            }
            else
            {
                ValidProcess = false;
            }
        }

        public bool IsValidPtr(IntPtr Address)
        {
            return (Address.ToInt64() >= 0x10000 && Address.ToInt64() < 0x000F000000000000);
        }

        public bool IsValidImagePtr(IntPtr Address)
        {
            return (Address.ToInt64() >= process.MainModule.BaseAddress.ToInt64() && 
                                                Address.ToInt64() < (process.MainModule.BaseAddress.ToInt64() + process.MainModule.ModuleMemorySize));
        }

        public IntPtr OpenProcessMemory()
        {
            processMemoryHandle = NativeMethods.OpenProcess(NativeMethods.PROCESS_VM_READ | NativeMethods.PROCESS_VM_WRITE |
                                                        NativeMethods.PROCESS_VM_OPERATION, false, process.Id);

            return processMemoryHandle;
        }

        public bool CloseProcessMemory()
        {
            return NativeMethods.CloseHandle(processMemoryHandle);
        }

        public bool ReadBuffer(ref byte[] Buffer, IntPtr address)
        {
            return NativeMethods.ReadProcessMemory(processMemoryHandle, (ulong)address.ToInt64(), Buffer, (uint)Buffer.Length, out IntPtr ByteRead);
        }

        public T Read<T>(IntPtr address)
        {
            byte[] Buffer = new byte[Marshal.SizeOf(typeof(T))];
            NativeMethods.ReadProcessMemory(processMemoryHandle, (ulong)address.ToInt64(), Buffer, (uint)Buffer.Length, out IntPtr ByteRead);

            GCHandle handle = GCHandle.Alloc(Buffer, GCHandleType.Pinned);
            T stuff = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();

            return stuff;
        }

        public bool Write<T>(IntPtr address, T t)
        {
            Byte[] Buffer = new Byte[Marshal.SizeOf(typeof(T))];
            GCHandle handle = GCHandle.Alloc(t, GCHandleType.Pinned);
            Marshal.Copy(handle.AddrOfPinnedObject(), Buffer, 0, Buffer.Length);
            handle.Free();

            NativeMethods.VirtualProtectEx(processMemoryHandle, address, (uint)Buffer.Length, NativeMethods.PAGE_READWRITE, out uint oldProtect);
            return NativeMethods.WriteProcessMemory(processMemoryHandle, (ulong)address.ToInt64(), Buffer, (uint)Buffer.Length, out IntPtr ptrBytesWritten);
        }

        public string ReadString(IntPtr address, UInt64 _Size)
        {
            byte[] buffer = new byte[_Size];

            NativeMethods.ReadProcessMemory(processMemoryHandle, (ulong)address.ToInt64(), buffer, _Size, out IntPtr BytesRead);

            var nullIndex = Array.IndexOf(buffer, (byte)0);
            nullIndex = (nullIndex == -1) ? (int)_Size : nullIndex;
            return Encoding.ASCII.GetString(buffer, 0, nullIndex);
        }

        private bool GetProcessesByName(string pName)
        {
            Process[] pList = Process.GetProcessesByName(pName);
            process = pList.Length > 0 ? pList[0] : null;
            return process != null;
        }
    }
}
