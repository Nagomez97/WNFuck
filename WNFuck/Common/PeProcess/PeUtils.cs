using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using WNFuck.Common.Interop;
using WNFuck.Common.Interop.NativeConsts;
using WNFuck.Common.WNF.Defines;

namespace WNFuck.Common.WNF.PeProcess
{
    public class PeUtils
    {
        public static Process GetProcessByName(string name)
        {
            Process[] processes = Process.GetProcessesByName(name);
            if (processes.Length == 0)
            {
                throw new ArgumentException($"[!] Process {name} could not be found.");
            }

            return processes[0];
        }

        public static IntPtr GetSubscriptionTablePtr(PeProcess proc)
        {
            if (proc.GetCurrentModuleName() != "ntdll.dll")
            {
                proc.SetBaseModule("ntdll.dll");
            }

            IntPtr pDataSection = proc.GetSectionAddress(".data");
            uint nSizeSubscriptionTable;
            uint nSizeDataSection = proc.GetSectionVirtualSize(".data");
            uint count;
            uint nSizePointer;
            WNF_CONTEXT_HEADER tableHeader;
            IntPtr pSubscriptionTable;
            IntPtr buffer;

            // Assuming x64 and Win11
            nSizeSubscriptionTable = (uint)Marshal.SizeOf(
                    typeof(WNF_SUBSCRIPTION_TABLE64_WIN11));
            nSizePointer = 8u;
            count = nSizeDataSection / nSizePointer;

            // Try to read sizeof(WNF_NODE_SUBSCRIPTION_TABLE) and check
            // Header->NoteTypeCode == 0x911
            for (var idx = 0u; idx < count; idx++)
            {
                pSubscriptionTable = proc.ReadIntPtr(pDataSection, idx * nSizePointer);

                if (proc.IsHeapAddress(pSubscriptionTable))
                {
                    buffer = proc.ReadMemory(pSubscriptionTable, nSizeSubscriptionTable);

                    if (buffer != IntPtr.Zero)
                    {
                        tableHeader = (WNF_CONTEXT_HEADER)Marshal.PtrToStructure(
                            buffer,
                            typeof(WNF_CONTEXT_HEADER));

                        NativeAPI.LocalFree(buffer);
                    }
                    else
                    {
                        continue;
                    }

                    if ((tableHeader.NodeTypeCode == Win32Consts.WNF_NODE_SUBSCRIPTION_TABLE) &&
                        (tableHeader.NodeByteSize == nSizeSubscriptionTable))
                    {
                        return pSubscriptionTable;
                    }
                }
            }

            return IntPtr.Zero;
        }

        public static WNF_SUBSCRIPTION_TABLE64_WIN11 PtrToSubscriptionTable(PeProcess proc, IntPtr pSubscriptionTable)
        {
            IntPtr buffer;
            uint nSizeSubscriptionTable;

            nSizeSubscriptionTable = (uint)Marshal.SizeOf(typeof(WNF_SUBSCRIPTION_TABLE64_WIN11));
            buffer = proc.ReadMemory(pSubscriptionTable, nSizeSubscriptionTable);

            var subscriptionTable = (WNF_SUBSCRIPTION_TABLE64_WIN11)Marshal.PtrToStructure(
                    buffer,
                    typeof(WNF_SUBSCRIPTION_TABLE64_WIN11));
            NativeAPI.LocalFree(buffer);

            return subscriptionTable;
        }

        public static WNF_NAME_SUBSCRIPTION64_WIN11 PtrToNameSubscription(PeProcess proc, IntPtr pNameSubscription)
        {
            IntPtr buffer;
            uint nSizeNameSubscription;

            nSizeNameSubscription = (uint)Marshal.SizeOf(typeof(WNF_NAME_SUBSCRIPTION64_WIN11));

            buffer = proc.ReadMemory(pNameSubscription, nSizeNameSubscription);

            if (buffer == IntPtr.Zero)
                throw new AccessViolationException("Could not read Name Subscription from process memory.");

            var nameSubscription = (WNF_NAME_SUBSCRIPTION64_WIN11)Marshal.PtrToStructure(
                buffer,
                typeof(WNF_NAME_SUBSCRIPTION64_WIN11));

            NativeAPI.LocalFree(buffer);

            return nameSubscription;
        }

        /// <summary>
        /// Walks the Red-Black Tree filling the list of NameSubscriptions
        /// </summary>
        /// <param name="proc"></param>
        /// <param name="pNameSubscription"></param>
        /// <param name="nameSubscriptions"></param>
        public static void ListWin11NameSubscriptions (PeProcess proc, IntPtr pNameSubscription, ref Dictionary<WELL_KNOWN_WNF_NAME, IntPtr> nameSubscriptions)
        {
            IntPtr pNameSubscriptionLeft;
            IntPtr pNameSubscriptionRight;

            // Get the offset
            uint nNameTableEntryOffset = (uint)Marshal.OffsetOf(
                    typeof(WNF_NAME_SUBSCRIPTION64_WIN11),
                    "NamesTableEntry").ToInt32();

            if (!proc.IsHeapAddress(pNameSubscription))
                return;

            var entry = PtrToNameSubscription(proc, pNameSubscription);

            // Check if Header.NodeTypeCode is the expected one
            if (!nameSubscriptions.ContainsKey((WELL_KNOWN_WNF_NAME)entry.StateName) && entry.Header.NodeTypeCode == Win32Consts.WNF_NODE_NAME_SUBSCRIPTION)
                nameSubscriptions.Add((WELL_KNOWN_WNF_NAME)entry.StateName, pNameSubscription);

            if (entry.NamesTableEntry.Left != 0L)
            {
                pNameSubscriptionLeft = new IntPtr(entry.NamesTableEntry.Left - nNameTableEntryOffset);
                ListWin11NameSubscriptions(proc, pNameSubscriptionLeft, ref nameSubscriptions);
            }

            if (entry.NamesTableEntry.Right != 0L)
            {
                pNameSubscriptionRight = new IntPtr(entry.NamesTableEntry.Right - nNameTableEntryOffset);
                ListWin11NameSubscriptions(proc, pNameSubscriptionRight, ref nameSubscriptions);
            }
        }

        public static IntPtr PatchUserSubscriptionCallback(PeProcess proc, IntPtr pUserSubscription, IntPtr pNewCallback, IntPtr pNewContext)
        {
            // Get the offset
            uint userTableCallbackOffset = (uint)Marshal.OffsetOf(
                    typeof(WNF_USER_SUBSCRIPTION64),
                    "Callback").ToInt32();

            IntPtr pCallback = pUserSubscription + (int) userTableCallbackOffset; // Gets a pointer to the callback address

            IntPtr lpNumberOfBytesWritten = IntPtr.Zero;
            if (!proc.WriteBytes(pCallback, pNewCallback, (uint) sizeof(Int64)))
            {
                return IntPtr.Zero;
            }

            if (pNewContext != IntPtr.Zero)
            {
                // Get the offset
                uint userTableContextOffset = (uint)Marshal.OffsetOf(
                        typeof(WNF_USER_SUBSCRIPTION64),
                        "CallbackContext").ToInt32();

                IntPtr pContextOriginal = pUserSubscription + (int)userTableContextOffset; // Gets a pointer to the callback address

                lpNumberOfBytesWritten = IntPtr.Zero;
                if (!proc.WriteBytes(pContextOriginal, pNewContext, (uint)sizeof(Int64)))
                {
                    return IntPtr.Zero;
                }
            }

            // Read the new callback from memory to check if it's correct
            IntPtr resultCallback = proc.ReadIntPtr(pCallback);

            return resultCallback;
        }

        public static Dictionary<IntPtr, WNF_CALLBACK> GetUserSubscriptionsFromNameSubscription(PeProcess proc, IntPtr pNameSubscription)
        {
            WNF_CALLBACK callback;
            var results = new Dictionary<IntPtr, WNF_CALLBACK>();
            uint nSizeUserSubscription;
            uint nSubscriptionsListEntryOffset;
            IntPtr pCurrentUserSubscription;
            IntPtr pFirstUserSubscription;
            IntPtr pUserSubscription;
            IntPtr buffer;
            WNF_USER_SUBSCRIPTION64 userSubscription;

            var nameSubscription = PeUtils.PtrToNameSubscription(proc, pNameSubscription);

            nSizeUserSubscription = (uint)Marshal.SizeOf(typeof(WNF_USER_SUBSCRIPTION64));
            nSubscriptionsListEntryOffset = (uint)Marshal.OffsetOf(
                typeof(WNF_USER_SUBSCRIPTION64),
                "SubscriptionsListEntry").ToInt32();

            pFirstUserSubscription = new IntPtr(nameSubscription.SubscriptionsListHead.Flink - nSubscriptionsListEntryOffset);
            pUserSubscription = pFirstUserSubscription;

            while (true)
            {
                pCurrentUserSubscription = pUserSubscription;
                buffer = proc.ReadMemory(pUserSubscription, nSizeUserSubscription);

                if (buffer == IntPtr.Zero)
                    break;

                userSubscription = (WNF_USER_SUBSCRIPTION64)Marshal.PtrToStructure(
                    buffer,
                    typeof(WNF_USER_SUBSCRIPTION64));
                NativeAPI.LocalFree(buffer);
                pUserSubscription = new IntPtr(userSubscription.SubscriptionsListEntry.Flink - nSubscriptionsListEntryOffset);

                if (pUserSubscription == pFirstUserSubscription)
                    break;

                callback = new WNF_CALLBACK {
                    Callback = new IntPtr(userSubscription.Callback),
                    CallbackContext = new IntPtr(userSubscription.CallbackContext)
                };

                results.Add(
                    pCurrentUserSubscription,
                    callback);
            }

            return results;
        }
    }
}
