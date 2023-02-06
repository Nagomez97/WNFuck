using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Permissions;

namespace WNFuck.Common.Interop
{
    public class SafeMemoryHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private bool _closed = false;
        public SafeMemoryHandle(IntPtr ptr) : base(true)
        {
            handle = ptr;
        }

        public static SafeMemoryHandle SafeAllocMemory(int size)
        {
            IntPtr ptr = Marshal.AllocHGlobal(size);
            return new SafeMemoryHandle(ptr);
        }


        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        override protected bool ReleaseHandle()
        {
            if (!_closed && handle != IntPtr.Zero)
            {
                _closed = true;
                return NativeAPI.LocalFree(handle) == IntPtr.Zero;
            }

            return true;
        }

        public void WriteByte(byte b)
        {
            Marshal.WriteByte(handle, b);
        }

        public void WriteString(string s)
        {
            int i = 0;
            foreach(byte c in s)
            {
                Marshal.WriteByte(handle, i, c);
                i++;
            }
        }

        public override string ToString()
        {
            return handle.ToString("X8");
        }
    }

}
