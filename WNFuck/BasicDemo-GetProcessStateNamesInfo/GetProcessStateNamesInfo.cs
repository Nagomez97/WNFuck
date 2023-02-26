using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using WNFuck.Common.Interop.NativeConsts;
using WNFuck.Common.WNF.Defines;
using WNFuck.Common.WNF.PeProcess;
using WNFuck.Common.WNF.Utils;

namespace WNFuck
{
    class GetStatenameInfo
    {
        static void Main(string[] args)
        {
            Console.SetWindowSize(130, Console.WindowHeight);

            Console.WriteLine("{0,-60}| {1,-17}| {2,-11}| {3,-10}| {4,-6}|MaxSize ",
                "WNF State Name",
                "Data Scope",
                "Lifetime",
                "Permanent",
                "Perms");

            Console.WriteLine(new string('-', 120));

            string processName = "EXPLORER";
            Process proc = null;
            PeProcess peProc = null;

            // Find the process by name and get first occurrence
            try
            {
                proc = PeUtils.GetProcessByName(processName);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return;
            }

            // Get the PeProcess object, used to parse the process memory
            // You may need SeDebugPrivilege for high privilege processes
            // Explorer should be just fine
            try
            {
                peProc = new PeProcess(proc.Id);
            }
            catch (ArgumentException ex)
            {
                Console.WriteLine($"[!] Could not open specified process.");
                return;
            }
            catch (KeyNotFoundException ex)
            {
                Console.WriteLine("[!] Failed to open the specified process.");
                return;
            }
            catch (Win32Exception ex)
            {
                Console.WriteLine($"[!] Failed to open the specified process. {ex.Message}");
                return;
            }

            foreach (var stateName in GetSubscribedStateNames(peProc))
            {
                FindStateNames(stateName, writable:false, hasAvailableBuffer:false);
            }
        }

        static List<WELL_KNOWN_WNF_NAME> GetSubscribedStateNames(PeProcess proc)
        {
            List<WELL_KNOWN_WNF_NAME> subscribedStateNames = new List<WELL_KNOWN_WNF_NAME>();

            #region _WNF_SUBSCRIPTION_TABLE
            // Find subscription table by iterating heap
            // and looking for NodeTypeCode 0x911
            IntPtr pSubscriptionTable = PeUtils.GetSubscriptionTablePtr(proc);
            if (pSubscriptionTable == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to get valid WNF_SUBSCRIPTION_TABLE.");
                return null;
            }

            // Get the _WNF_SUBSCRIPTION_TABLE struct
            var subscriptionTable = PeUtils.PtrToSubscriptionTable(proc, pSubscriptionTable);
            #endregion

            #region _WNF_NAME_SUBSCRIPTION root
            uint nNameTableEntryOffset;
            IntPtr pNameSubscription;

            nNameTableEntryOffset = (uint)Marshal.OffsetOf(
                typeof(WNF_NAME_SUBSCRIPTION64_WIN11),
                "NamesTableEntry").ToInt32();

            // NamesTableEntry->Root does not point to the beginning of a _WNF_NAME_SUBSCRIPTION,
            // but instead it points to the NamesTableEntry property, so we need to substract the offset
            pNameSubscription = new IntPtr(subscriptionTable.NamesTableEntry.Root - nNameTableEntryOffset);
            var nameSubscriptionRoot = PeUtils.PtrToNameSubscription(proc, pNameSubscription);
            #endregion

            #region List NameSubscriptions
            Dictionary<WELL_KNOWN_WNF_NAME, IntPtr> nameSubscriptions = new Dictionary<WELL_KNOWN_WNF_NAME, IntPtr>();

            // Walks the Red-Black Tree filling the list of NameSubscriptions
            PeUtils.ListWin11NameSubscriptions(proc, pNameSubscription, ref nameSubscriptions);
            #endregion

            // Very inefficient but in a rush
            foreach (var stateName in nameSubscriptions.Keys )
            {
                subscribedStateNames.Add(stateName);
            }

            return subscribedStateNames;
        }

        static void FindStateNames(WELL_KNOWN_WNF_NAME stateName, bool readable = false, bool writable = false, bool hasAvailableBuffer = false)
        {
            WNF_STATE_NAME_STRUCT stateNameStruct = Utils.GetStructFromStateName((ulong)stateName);
            byte[] securityDescriptor = Utils.GetSecurityDescriptor(stateName);
            //string securityDescriptorStr = Utils.GetStateNameSecurityDescriptorAsString(securityDescriptor); // Best way of knowing if you can read/write is to actively try. However, you can parse the ACEs in the DACL.

            int maxSize = -1;
            if (securityDescriptor != null )
            {
                maxSize = Utils.GetWNFBufferMaxSize(securityDescriptor);
            }
             

            // Try to read/write StateName
            bool canRead = Utils.CanReadStateName(stateName, out int bufferSize);
            bool canWrite = Utils.CanWriteStateName(stateName);

            if ((!canRead && readable) || (!canWrite && writable) || (hasAvailableBuffer && maxSize <= 1024)) return;

            // Print results
            Console.WriteLine("{0,-60}| {1,-17}| {2,-11}| {3,-10}| {4,-6}| {5,-4}",
                stateName,
                stateNameStruct.DataScope,
                stateNameStruct.NameLifetime,
                stateNameStruct.PermanentData,
                canRead && canWrite ? "RW" : (canRead ? "RO" : (canWrite ? "WO" : "N/A")),
                maxSize);

            //Console.WriteLine(securityDescriptorStr);
        }
    }
}
