using System;
using WNFuck.Common.Interop;
using WNFuck.Common.WNF.Enums;

namespace WNFuck
{
    internal class Client
    {
        static void Main(string[] args)
        {
            WELL_KNOWN_WNF_NAME stateName = WELL_KNOWN_WNF_NAME.WNF_XBOX_ACHIEVEMENT_TRACKER_STATE_CHANGED;
            Console.WriteLine($"[+] WNF Client started. Press any key to send a {stateName} notification.");
            Console.ReadLine();

            string data = "Hi there!";

            using (var handle = SafeMemoryHandle.SafeAllocMemory(data.Length))
            using (var nullHandle = new SafeMemoryHandle(IntPtr.Zero))
            {
                handle.WriteString(data);

                var res = NativeAPI.NtUpdateWnfStateData(stateName, handle, data.Length, IntPtr.Zero, nullHandle, 0, 0);
                if (res == Common.Interop.NativeConsts.NtStatus.AccessDenied)
                {
                    Console.WriteLine($"[!] Access denied. You need write permissions over {stateName}");
                }
            }
            

            
        }
    }
}
