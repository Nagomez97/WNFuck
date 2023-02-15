using System;
using System.Text;
using WNFuck.Common.Interop;
using WNFuck.Common.WNF.Defines;

namespace WNFuck
{
    internal class Client
    {
        static void Main(string[] args)
        {
            //WELL_KNOWN_WNF_NAME stateName = WELL_KNOWN_WNF_NAME.WNF_XBOX_ACHIEVEMENT_TRACKER_STATE_CHANGED;

            WELL_KNOWN_WNF_NAME stateName = (WELL_KNOWN_WNF_NAME)0x41C64E6DA2304845;
            Console.WriteLine($"[+] WNF Client started. Press any key to send a {stateName} notification.");

            string data = "Hi there!";
            byte[] bData = Encoding.ASCII.GetBytes(data);

            var res = NativeAPI.NtUpdateWnfStateData(stateName, bData, bData.Length, IntPtr.Zero, IntPtr.Zero, 0, 0);
            if (res == Common.Interop.NativeConsts.NtStatus.AccessDenied)
            {
                Console.WriteLine($"[!] Access denied. You need write permissions over {stateName}");
            }
            else if (res != Common.Interop.NativeConsts.NtStatus.Success)
            {
                Console.WriteLine($"[!] Error updating WNF State Data: {res}");
            }
        }
    }
}
