using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using WNFuck.Common.Interop.NativeConsts;
using WNFuck.Common.WNF.Defines;
using WNFuck.Common.WNF.PeProcess;

namespace WNFuck
{
    internal class CallbackParser
    {
        static void Main(string[] args)
        {
            string processName = "EXPLORER";
            Process proc = null;
            PeProcess peProc = null;

            Console.WriteLine($"[+] Trying to get WNF subscriptions for process {processName}\n");

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
            catch(ArgumentException ex)
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

                #region Get UserSubscriptions
                foreach (WELL_KNOWN_WNF_NAME stateName in nameSubscriptions.Keys)
                {
                    pNameSubscription = nameSubscriptions[stateName];

                    var userSubscriptions = PeUtils.GetUserSubscriptionsFromNameSubscription(peProc, pNameSubscription);

                    Console.WriteLine();
                    Console.WriteLine($"[+] {stateName} @ 0x{pNameSubscription.ToString("X16")}");
                    
                    foreach(var userSub in userSubscriptions)
                    {
                        Console.WriteLine($"\t-> Callback @ 0x{userSub.Value.Callback} | Context @ 0x{userSub.Value.CallbackContext}");
                    }

                    Console.WriteLine();

                }
                #endregion

                pNameSubscription = nameSubscriptions[WELL_KNOWN_WNF_NAME.WNF_CAM_MICROPHONE_USAGE_CHANGED];

                var userSubscriptions2 = PeUtils.GetUserSubscriptionsFromNameSubscription(peProc, pNameSubscription);

                Console.WriteLine();
                Console.WriteLine($"[+] {WELL_KNOWN_WNF_NAME.WNF_CAM_MICROPHONE_USAGE_CHANGED} @ 0x{pNameSubscription.ToString("X16")}");

                foreach (var userSub in userSubscriptions2)
                {
                    Console.WriteLine($"\t-> Callback @ 0x{userSub.Value.Callback.ToString("X16")} | Context @ 0x{userSub.Value.CallbackContext.ToString("X16")}");
                }

                Console.ReadLine();
            }
        }
    }
}
