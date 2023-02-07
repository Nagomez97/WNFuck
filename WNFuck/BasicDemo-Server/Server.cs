using System;
using System.Runtime.InteropServices;
using WNFuck.Common.Interop;
using WNFuck.Common.Interop.NativeConsts;
using WNFuck.Common.WNF.Enums;
using WNFuck.Common.HexDump;
using System.Threading;

namespace WNFuck
{
    internal class Server
    {
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

        static void Main(string[] args)
        {
            NtStatus ntstatus;
            IntPtr hEvent = IntPtr.Zero;
            IntPtr pContextBuffer = IntPtr.Zero;
            IntPtr pSubscription = IntPtr.Zero;

            Server s = new Server();

            WELL_KNOWN_WNF_NAME stateName = WELL_KNOWN_WNF_NAME.WNF_XBOX_ACHIEVEMENT_TRACKER_STATE_CHANGED;
            Console.WriteLine($"[+] WNF Server started.");

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
