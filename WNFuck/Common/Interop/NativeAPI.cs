using System;
using System.Runtime.InteropServices;
using WNFuck.Common.WNF.Enums;

namespace WNFuck.Common.Interop
{
    public static class NativeAPI
    {
        #region KERNEL32
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LocalFree(IntPtr hMem);
        #endregion

        #region NTDLl
        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern NativeConsts.NtStatus NtUpdateWnfStateData(
            in WELL_KNOWN_WNF_NAME StateName, 
            SafeMemoryHandle Buffer, 
            int Length, IntPtr TypeId, 
            SafeMemoryHandle ExplicitScope, 
            int MatchingChangeScope, 
            int CheckStamp);

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
        public static extern NativeConsts.NtStatus RtlUnsubscribeWnfStateChangeNotification(
            IntPtr Subscription);

        [DllImport("ntdll.dll")]
        public static extern NativeConsts.NtStatus NtCreateWnfStateName(
            out WELL_KNOWN_WNF_NAME StateName,
            WNF_STATE_NAME_LIFETIME NameLifetime,
            WNF_DATA_SCOPE DataScope,
            bool PersistData,
            IntPtr TypeId,
            int MaximumStateSize,
            IntPtr SecurityDescriptor);

        [DllImport("ntdll.dll")]
        public static extern NativeConsts.NtStatus NtQueryWnfStateData(
            in WELL_KNOWN_WNF_NAME StateName,
            IntPtr TypeId,
            IntPtr ExplicitScope,
            out int ChangeStamp,
            SafeMemoryHandle Buffer,
            ref int BufferSize);
        #endregion
    }
}
