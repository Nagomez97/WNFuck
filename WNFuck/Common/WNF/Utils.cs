using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using WNFuck.Common.Interop;
using WNFuck.Common.Interop.NativeConsts;
using WNFuck.Common.WNF.Defines;

namespace WNFuck.Common.WNF.Utils
{
    public class Utils
    {
        public const ulong WNF_STATE_KEY = 0x41C64E6DA3BC0074;
        public const int SDDL_REVISION_1 = 1;
        public const string WELL_KNOWN_STATE_NAMES_REGKEY = @"SYSTEM\CurrentControlSet\Control\Notifications";

        public static int GetWNFBufferMaxSize(byte[] securityDescriptor)
        {
            int sdSize = NativeAPI.GetSecurityDescriptorLength(securityDescriptor);
            int maxSize = BitConverter.ToInt32(securityDescriptor, sdSize);

            return maxSize;
        }

        public static WNF_STATE_NAME_STRUCT GetStructFromStateName(ulong stateName)
        {
            WNF_STATE_NAME_STRUCT stateStruct;

            stateName ^= WNF_STATE_KEY;
            stateStruct.Version = stateName & 0xF;
            stateStruct.NameLifetime = (WNF_STATE_NAME_LIFETIME) ((stateName >> 4) & 0x3);
            stateStruct.DataScope = (WNF_DATA_SCOPE) ((stateName >> 6) & 0xF);

            ulong pData = (stateName >> 10) & 0x1;
            stateStruct.PermanentData = (pData == 0) ? false : true;
            stateStruct.SequenceNumber = (stateName >> 11) & 0x1FFFFF;
            stateStruct.OwnerTag = (stateName >> 32) & 0xFFFFFFFF;

            return stateStruct;
        }

        public static List<WELL_KNOWN_WNF_NAME> GetAllWellKnownStateNames()
        {
            List<WELL_KNOWN_WNF_NAME> wellKnownNames = new List<WELL_KNOWN_WNF_NAME>();

            using (RegistryKey regKey = Registry.LocalMachine.OpenSubKey(WELL_KNOWN_STATE_NAMES_REGKEY))
            {
                if (regKey != null)
                {
                    string[] values = regKey.GetValueNames();

                    foreach (string value in values)
                    {
                        wellKnownNames.Add((WELL_KNOWN_WNF_NAME)Convert.ToInt64(value, 16));
                    }
                }
            }

            return wellKnownNames;
        }

        public static byte[] GetSecurityDescriptor(WELL_KNOWN_WNF_NAME stateName)
        {
            using (RegistryKey regKey = Registry.LocalMachine.OpenSubKey(WELL_KNOWN_STATE_NAMES_REGKEY))
            {
                string stateValue = string.Format("{0:X16}", (ulong)stateName);
                byte[] securityDescriptor = (byte[])regKey.GetValue(stateValue);

                if (NativeAPI.IsValidSecurityDescriptor(securityDescriptor))
                {
                    return securityDescriptor;
                }
                else
                {
                    return null;
                }
            }
        }

        public static string GetStateNameSecurityDescriptorAsString(byte[] securityDescriptor)
        {
            if (NativeAPI.ConvertSecurityDescriptorToStringSecurityDescriptor(securityDescriptor, SDDL_REVISION_1, Interop.NativeConsts.SECURITY_INFORMATION.DACL_SECURITY_INFORMATION, out StringBuilder securityDescriptorStr, IntPtr.Zero))
            {
                return securityDescriptorStr.ToString();
            }

            return null;
        }

        public static bool CanWriteStateName(WELL_KNOWN_WNF_NAME stateName)
        {
            NtStatus status = NativeAPI.NtUpdateWnfStateData(
                in stateName,
                null,
                0,
                IntPtr.Zero,
                IntPtr.Zero,
                -1,
                1);

            return status == NtStatus.Success || status == NtStatus.Unsuccessful;
        }

        public static bool CanReadStateName(WELL_KNOWN_WNF_NAME stateName, out int bufferSize)
        {
            var res = ReadWNFData(stateName, out int stamp, out byte[] buffer, out bufferSize);

            return res;
        }

        public static bool ReadWNFData(WELL_KNOWN_WNF_NAME stateName, out int stamp, out byte[] dataBuffer, out int bufferSize)
        {
            stamp = 0;
            bufferSize = 0;

            dataBuffer = null;

            // First call to get the buffer size
            NtStatus status = NativeAPI.NtQueryWnfStateData(stateName, IntPtr.Zero, IntPtr.Zero, out stamp, null, out bufferSize);

            if (status == NtStatus.BufferTooSmall)
            {
                dataBuffer = new byte[bufferSize];
                status = NativeAPI.NtQueryWnfStateData(stateName, IntPtr.Zero, IntPtr.Zero, out stamp, dataBuffer, out bufferSize);

                return status == NtStatus.Success;
            }
            else if (status == NtStatus.AccessDenied)
            {
                return false;
            }
            return true;
        }
    }
}
