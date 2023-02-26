using System;
using System.Runtime.InteropServices;
using System.Text;
using WNFuck.Common.Interop.NativeConsts;
using WNFuck.Common.WNF.Defines;
using static WNFuck.Common.WNF.PeProcess.PeProcess;

namespace WNFuck.Common.Interop
{
    public static class NativeAPI
    {
        #region KERNEL32
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("kernel32", SetLastError = true)]
        public static extern bool VirtualFree(
            IntPtr lpAddress,
            int dwSize,
            AllocationType dwFreeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress,
            uint dwSize, MemoryAllocationFlags dwFreeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAllocEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            uint dwSize,
            MemoryAllocationFlags flAllocationType,
            MemoryProtectionFlags flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualProtectEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            uint dwSize,
            MemoryProtectionFlags flNewProtect,
            out MemoryProtectionFlags lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            uint nSize,
            out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            ref IntPtr lpBuffer,
            uint nSize,
            out IntPtr lpNumberOfBytesWritten);
        #endregion

        #region NTDLl
        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern NativeConsts.NtStatus NtUpdateWnfStateData(
            in WELL_KNOWN_WNF_NAME StateName, 
            byte[] Buffer, 
            int Length, IntPtr TypeId, 
            IntPtr ExplicitScope, 
            int MatchingChangeScope, 
            int CheckStamp);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern NativeConsts.NtStatus NtDeleteWnfStateData(
            ulong StateName,
            IntPtr ExplicitScope);

        [DllImport("ntdll.dll")]
        public static extern NativeConsts.NtStatus RtlSubscribeWnfStateChangeNotification(
            out IntPtr Subscription,
            WELL_KNOWN_WNF_NAME StateName,
            int ChangeStamp,
            IntPtr Callback,
            IntPtr CallbackContext,
            IntPtr TypeId,
            int SerializationGroup,
            int Unknown);

        [DllImport("ntdll.dll")]
        public static extern NativeConsts.NtStatus RtlSubscribeWnfStateChangeNotification(
            out IntPtr Subscription,
            ulong StateName,
            int ChangeStamp,
            IntPtr Callback,
            IntPtr CallbackContext,
            IntPtr TypeId,
            int SerializationGroup,
            int Unknown);

        [DllImport("ntdll.dll")]
        public static extern NativeConsts.NtStatus RtlUnsubscribeWnfStateChangeNotification(
            IntPtr Subscription);

        [DllImport("ntdll.dll")]
        public static extern NativeConsts.NtStatus NtCreateWnfStateName(
            out ulong StateName,
            WNF_STATE_NAME_LIFETIME NameLifetime,
            WNF_DATA_SCOPE DataScope,
            bool PersistData,
            IntPtr TypeId,
            int MaximumStateSize,
            SafeMemoryHandle SecurityDescriptor);

        [DllImport("ntdll.dll")]
        public static extern NativeConsts.NtStatus NtDeleteWnfStateName(ulong StateName);

        [DllImport("ntdll.dll")]
        public static extern NativeConsts.NtStatus NtQueryWnfStateData(
            in WELL_KNOWN_WNF_NAME StateName,
            IntPtr TypeId,
            IntPtr ExplicitScope,
            out int ChangeStamp,
            byte[] Buffer,
            out int BufferSize);
        #endregion

        #region ADVAPI32
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool IsValidSecurityDescriptor(byte[] pSecurityDescriptor);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool ConvertSecurityDescriptorToStringSecurityDescriptor(
            byte[] pSecurityDescriptor,
            int RequestedStringSDRevision,
            SECURITY_INFORMATION SecurityInformation,
            out StringBuilder StringSecurityDescriptor,
            IntPtr StringSecurityDescriptorLen);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
          string StringSecurityDescriptor,
          uint StringSDRevision,
          out IntPtr SecurityDescriptor,
          out ulong SecurityDescriptorSize);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern int GetSecurityDescriptorLength(byte[] pSecurityDescriptor);
        #endregion
    }
}
