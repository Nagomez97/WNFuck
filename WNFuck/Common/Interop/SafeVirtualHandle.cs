using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Permissions;

namespace WNFuck.Common.Interop
{
    public class SafeVirtualHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private bool _closed = false;
        private int _size;
        public SafeVirtualHandle(IntPtr ptr, int size) : base(true)
        {
            handle = ptr;
            _size = size;

            if (size <= 0)
            {
                throw new ArgumentOutOfRangeException("size");
            }
        }

        public static SafeMemoryHandle SafeAllocMemory(int size)
        {
            IntPtr ptr = Marshal.AllocHGlobal(size);
            return new SafeMemoryHandle(ptr);
        }

        public byte[] ToByteArray()
        {
            byte[] data = new byte[_size];
            Marshal.Copy(handle, data, 0, _size);

            return data;
        }


        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        override protected bool ReleaseHandle()
        {
            if (!_closed && handle != IntPtr.Zero)
            {
                _closed = true;
                return NativeAPI.VirtualFree(handle, _size, NativeConsts.Win32Consts.MEM_RELEASE);
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
            foreach (byte c in s)
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
