using System;
using WNFuck.Common.WNF.Defines;
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

            //foreach (var stateName in Utils.GetAllWellKnownStateNames())
            //{
            //    FindStateNames(stateName, readable: false, writable: true, hasAvailableBuffer: true);
            //}

            WELL_KNOWN_WNF_NAME stateName = WELL_KNOWN_WNF_NAME.WNF_CAM_MICROPHONE_USAGE_CHANGED;
            FindStateNames(stateName);
        }

        static void FindStateNames(WELL_KNOWN_WNF_NAME stateName, bool readable = false, bool writable = false, bool hasAvailableBuffer = false)
        {
            WNF_STATE_NAME_STRUCT stateNameStruct = Utils.GetStructFromStateName((ulong)stateName);
            byte[] securityDescriptor = Utils.GetSecurityDescriptor(stateName);
            string securityDescriptorStr = Utils.GetStateNameSecurityDescriptorAsString(securityDescriptor); // Best way of knowing if you can read/write is to actively try. However, you can parse the ACEs in the DACL.

            int maxSize = Utils.GetWNFBufferMaxSize(securityDescriptor);

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
