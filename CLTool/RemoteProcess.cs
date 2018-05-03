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
