using System;
using System.Collections.Generic;
using System.Data.Common;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using WNFuck.Common.HexDump;
using WNFuck.Common.Interop;
using WNFuck.Common.Interop.NativeConsts;
using WNFuck.Common.WNF.Defines;
using WNFuck.Common.WNF.Utils;

namespace WNFuck
{
    class Program
    {
        static void Main(string[] args)
        {
            Persistor persistor = new Persistor();

            string data = new string('A', 4096 * 10);
            byte[] bData = Encoding.ASCII.GetBytes(data);

            persistor.Persist(bData);

            Console.WriteLine($"[+] Data persisted into multiple temporary names. Press any key to continue.");
            Console.ReadLine();

            ulong[] stateNames = GetTemporaryStateNames();

            Console.ReadLine();

            foreach(var sn in stateNames)
            {
                if (Utils.ReadWNFData((WELL_KNOWN_WNF_NAME)sn, out int stamp, out byte[] dataBuffer, out int bufferSize))
                {
                    Console.WriteLine();
                    Console.WriteLine($"[+] Received {(WELL_KNOWN_WNF_NAME)sn} data.");
                    Console.WriteLine("    |-> Timestamp : {0}", stamp);
                    Console.WriteLine("    |-> Buffer Size : {0} byte(s)", bufferSize);
                    Console.WriteLine("    |-> Data :\n");
                    HexDump.Dump(dataBuffer, (uint)bufferSize, 2);
                }

                // Cleanup
                NativeAPI.NtDeleteWnfStateName(sn);
            }

            // Clean WellKnown StateName Data
            NativeAPI.NtDeleteWnfStateData((ulong)Persistor.WellKnownStateName, IntPtr.Zero);

            Console.WriteLine("[+] StateNames and data deleted. Press any key to exit.");
            Console.ReadLine();
        }

        // Queries WNF_XBOX_ACHIEVEMENTS_RAW_NOTIFICATION_RECEIVED to get a list of temporary StateNames for persitency
        static ulong[] GetTemporaryStateNames()
        {
            if (!Utils.ReadWNFData(Persistor.WellKnownStateName, out int stamp, out byte[] dataBuffer, out int bufferSize))
            {
                return null;
            }

            int nStateNames = bufferSize / sizeof(ulong); // Should be exact

            Console.WriteLine($"[+] Getting {nStateNames} persisted StateNames");
            ulong[] stateNames = new ulong[nStateNames];

            for (int i = 0; i < nStateNames; i++)
            {
                byte[] ulongbytes = new byte[sizeof(ulong)];
                Array.Copy(dataBuffer, i * sizeof(ulong), ulongbytes, 0, sizeof(ulong));

                ulong stateName = (ulong) BitConverter.ToInt64(ulongbytes, 0);

                Console.WriteLine($"\t-> 0x{stateName.ToString("X16")}");
                stateNames[i] = stateName;
            }

            return stateNames;
        }
    }

    class Persistor
    {
        private string SDString = "D:(A;;CCDC;;;WD)"; // Only creator can RW
        public static WELL_KNOWN_WNF_NAME WellKnownStateName = WELL_KNOWN_WNF_NAME.WNF_XBOX_ACHIEVEMENTS_RAW_NOTIFICATION_RECEIVED;

        public void Persist(byte[] data)
        {
            // Create as many Temporary state names as needed
            int nStateNames = (int) Math.Ceiling(((float)data.Length / (float)4096));
            ulong[] stateNames = new ulong[nStateNames];
            byte[] stateNamesBytes = new byte[nStateNames * sizeof(ulong)];

            // Create temporary State Names
            Console.WriteLine($"[+] Trying to create {nStateNames} temporary names to store {data.Length} bytes...");
            for (int i = 0; i < nStateNames; i++)
            {
                ulong tempStateName = Utils.CreateTemporaryStateName(SDString, WNF_DATA_SCOPE.USER, 4096);
                if (tempStateName != 0)
                {
                    stateNames[i] = tempStateName;
                    Console.WriteLine($"\t-> 0x{tempStateName.ToString("X16")}");
                }
                else
                {
                    // Cleanup
                    foreach (var sn in stateNames)
                    {
                        NativeAPI.NtDeleteWnfStateName(sn);
                    }

                    return;
                }

                // Fill the bytearray of statenames to be published in the WellKnown StateName
                byte[] longBytes = BitConverter.GetBytes(tempStateName);
                Array.Copy(longBytes, 0, stateNamesBytes, i * sizeof(ulong), sizeof(ulong));
            }

            // Publish StateNames bytearray into WellKnown 
            var status = NativeAPI.NtUpdateWnfStateData(
                WellKnownStateName,
                stateNamesBytes,
                stateNamesBytes.Length,
                IntPtr.Zero,
                IntPtr.Zero,
                0,
                0);

            if (status != NtStatus.Success)
            {
                Console.WriteLine($"[!] Error saving persisted StateNames! {status}");
            }

            // Publish data into temporary state names
            Console.WriteLine($"[+] Start writing data on temporary state names.");
            for (int i = 0; i < nStateNames; i++)
            {
                var currentStateName = stateNames[i];
                byte[] chunk = new byte[4096];
                Array.Copy(data, 4096 * i, chunk, 0, 4096);

                // Publish chunk
                var res = NativeAPI.NtUpdateWnfStateData(
                    (WELL_KNOWN_WNF_NAME)currentStateName,
                    chunk,
                    4096,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    0,
                    0);

                if (res != NtStatus.Success)
                {
                    Console.WriteLine($"[!] Could not write data in 0x{currentStateName.ToString("X16")}. {res}");
                }
            }
        }
    }
}
