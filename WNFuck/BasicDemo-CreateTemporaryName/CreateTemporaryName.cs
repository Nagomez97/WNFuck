using System;
using System.Runtime.InteropServices;
using System.Threading;
using WNFuck.Common.HexDump;
using WNFuck.Common.Interop;
using WNFuck.Common.Interop.NativeConsts;
using WNFuck.Common.WNF.Defines;
using WNFuck.Common.WNF.Utils;

namespace WNFuck
{
    internal class Server
    {
        static void Main(string[] args)
        {
            string sdString = "D:(A;;CCDC;;;WD)"; // All users can RW

            // Creates a temporar WNF State Name which
            // will be available as long as this process lives
            ulong stateName = CreateTemporaryStateName(sdString);

            if (stateName == 0)
            {
                Console.WriteLine("[!] Error creating StateName!");
            }

            Listen(stateName);
        }

        internal static ulong CreateTemporaryStateName(string sdString)
        {
            if (NativeAPI.ConvertStringSecurityDescriptorToSecurityDescriptor(
                sdString,
                Utils.SDDL_REVISION_1,
                out IntPtr securityDescriptor,
                out ulong sdSize))
            {
                using (SafeMemoryHandle safeSD = new SafeMemoryHandle(securityDescriptor)) // needs to be freed
                {
                    NtStatus status = NativeAPI.NtCreateWnfStateName(
                        out ulong stateName,
                        Common.WNF.Defines.WNF_STATE_NAME_LIFETIME.TEMPORARY, // If this process dies, the WNF Name will no longer be available
                        Common.WNF.Defines.WNF_DATA_SCOPE.SYSTEM,
                        false,
                        IntPtr.Zero,
                        4096,
                        safeSD);

                    if (status != NtStatus.Success)
                    {
                        Console.WriteLine($"[!] Could not create new WNF State Name! {status}");
                        return 0;
                    }

                    Console.WriteLine("[+] New WNF State Name is created successfully : 0x{0}\n", stateName.ToString("X16"));
                    return stateName;
                }

            }

            return 0;
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate NtStatus CallbackDelegate(
            ulong StateName,
            int ChangeStamp,
            IntPtr TypeId,
            IntPtr CallbackContext,
            IntPtr Buffer,
            int BufferSize);

        private NtStatus NotifyCallback(
            ulong stateName,
            int nChangeStamp,
            IntPtr pTypeId,
            IntPtr pCallbackContext,
            IntPtr pBuffer,
            int nBufferSize)
        {
            if (pBuffer != IntPtr.Zero && nBufferSize == 0 && nChangeStamp == 0)
            {
                Console.WriteLine();
                Console.WriteLine("[*] WNF State Name is destroyed.");
                Console.WriteLine();
            }
            else
            {
                Console.WriteLine();
                Console.WriteLine($"[+] Received {(WELL_KNOWN_WNF_NAME)stateName} data.");
                Console.WriteLine("    |-> Timestamp : {0}", nChangeStamp);
                Console.WriteLine("    |-> Buffer Size : {0} byte(s)", nBufferSize);
                Console.WriteLine("    |-> Data :\n");

                HexDump.Dump(pBuffer, (uint)nBufferSize, 2);

                Console.WriteLine();
            }

            return NtStatus.Success;
        }
            
        internal static void Listen(ulong stateName)
        {
            NtStatus ntstatus;
            IntPtr hEvent = IntPtr.Zero;
            IntPtr pContextBuffer = IntPtr.Zero;
            IntPtr pSubscription = IntPtr.Zero;

            Server s = new Server();

            Console.WriteLine($"[+] WNF Server started. Execute client with current StateName to interact.");

            IntPtr pCallback = Marshal.GetFunctionPointerForDelegate(new CallbackDelegate(s.NotifyCallback));

            ntstatus = NativeAPI.RtlSubscribeWnfStateChangeNotification(
                    out pSubscription,
                    stateName,
                    0,
                    pCallback,
                    pContextBuffer,
                    IntPtr.Zero,
                    0,
                    0);

            if (ntstatus != NtStatus.Success)
            {
                Console.WriteLine();
                Console.WriteLine($"[!] Could not subscribe to {stateName}!");
                Console.WriteLine();

                return;
            }

            do
            {
                Thread.Sleep(5000);
            } while (true);
        }
    }
}
