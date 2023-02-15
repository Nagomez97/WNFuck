using System;
using WNFuck.Common.HexDump;
using WNFuck.Common.WNF.Defines;
using WNFuck.Common.WNF.Utils;

namespace WNFuck
{
    internal class Consumer
    {
        static void Main(string[] args)
        {
            WELL_KNOWN_WNF_NAME stateName = WELL_KNOWN_WNF_NAME.WNF_XBOX_ACHIEVEMENT_TRACKER_STATE_CHANGED;

            Console.WriteLine($"[+] Consumer for {stateName} started...");
            if (Utils.ReadWNFData(stateName, out int stamp, out byte[] dataBuffer, out int bufferSize))
            {
                Console.WriteLine();
                Console.WriteLine($"[+] Received {(WELL_KNOWN_WNF_NAME)stateName} data.");
                Console.WriteLine("    |-> Timestamp : {0}", stamp);
                Console.WriteLine("    |-> Buffer Size : {0} byte(s)", bufferSize);
                Console.WriteLine("    |-> Data :\n");
                HexDump.Dump(dataBuffer, (uint)bufferSize, 2);
            }
            else
            {
                Console.WriteLine("[!] You don't have read privileges over the given State Name.");
            }

        }
    }
}
