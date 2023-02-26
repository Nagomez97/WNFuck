﻿using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using WNFuck.Common.Interop;

namespace WNFuck.Common.WNF.PeProcess
{
    public class PeProcess : IDisposable
    {
        #region Enums
        /*
         * P/Invoke : Enums
         */
        public enum AllocationProtectEnum : uint
        {
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400
        }

        [Flags]
        public enum AllocationType
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Release = 0x8000,
            Reset = 0x80000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            LargePages = 0x20000000
        }

        public enum DllCharacteristicsType : ushort
        {
            RES_0 = 0x0001,
            RES_1 = 0x0002,
            RES_2 = 0x0004,
            RES_3 = 0x0008,
            IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 0x0040,
            IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY = 0x0080,
            IMAGE_DLL_CHARACTERISTICS_NX_COMPAT = 0x0100,
            IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200,
            IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400,
            IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800,
            RES_4 = 0x1000,
            IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
            IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
        }

        public enum MagicType : ushort
        {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
            IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
        }

        [Flags]
        public enum LocalMemoryFlags
        {
            LMEM_FIXED = 0x0000,
            LMEM_MOVEABLE = 0x0002,
            LMEM_NOCOMPACT = 0x0010,
            LMEM_NODISCARD = 0x0020,
            LMEM_ZEROINIT = 0x0040,
            LMEM_MODIFY = 0x0080,
            LMEM_DISCARDABLE = 0x0F00,
            LMEM_VALID_FLAGS = 0x0F72,
            LMEM_INVALID_HANDLE = 0x8000,
            LHND = (LMEM_MOVEABLE | LMEM_ZEROINIT),
            LPTR = (LMEM_FIXED | LMEM_ZEROINIT),
            NONZEROLHND = (LMEM_MOVEABLE),
            NONZEROLPTR = (LMEM_FIXED)
        }

        [Flags]
        public enum MemoryProtection
        {
            Execute = 0x10,
            ExecuteRead = 0x20,
            ExecuteReadWrite = 0x40,
            ExecuteWriteCopy = 0x80,
            NoAccess = 0x01,
            ReadOnly = 0x02,
            ReadWrite = 0x04,
            WriteCopy = 0x08,
            GuardModifierflag = 0x100,
            NoCacheModifierflag = 0x200,
            WriteCombineModifierflag = 0x400
        }

        public enum PROCESSINFOCLASS
        {
            ProcessBasicInformation, // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
            ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
            ProcessIoCounters, // q: IO_COUNTERS
            ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
            ProcessTimes, // q: KERNEL_USER_TIMES
            ProcessBasePriority, // s: KPRIORITY
            ProcessRaisePriority, // s: ULONG
            ProcessDebugPort, // q: HANDLE
            ProcessExceptionPort, // s: PROCESS_EXCEPTION_PORT (requires SeTcbPrivilege)
            ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
            ProcessLdtInformation, // qs: PROCESS_LDT_INFORMATION // 10
            ProcessLdtSize, // s: PROCESS_LDT_SIZE
            ProcessDefaultHardErrorMode, // qs: ULONG
            ProcessIoPortHandlers, // (kernel-mode only) // PROCESS_IO_PORT_HANDLER_INFORMATION
            ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
            ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
            ProcessUserModeIOPL, // qs: ULONG (requires SeTcbPrivilege)
            ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
            ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
            ProcessWx86Information, // qs: ULONG (requires SeTcbPrivilege) (VdmAllowed)
            ProcessHandleCount, // q: ULONG, PROCESS_HANDLE_INFORMATION // 20
            ProcessAffinityMask, // (q >WIN7)s: KAFFINITY, qs: GROUP_AFFINITY
            ProcessPriorityBoost, // qs: ULONG
            ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
            ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
            ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
            ProcessWow64Information, // q: ULONG_PTR
            ProcessImageFileName, // q: UNICODE_STRING
            ProcessLUIDDeviceMapsEnabled, // q: ULONG
            ProcessBreakOnTermination, // qs: ULONG
            ProcessDebugObjectHandle, // q: HANDLE // 30
            ProcessDebugFlags, // qs: ULONG
            ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: size 0 disables, otherwise enables
            ProcessIoPriority, // qs: IO_PRIORITY_HINT
            ProcessExecuteFlags, // qs: ULONG
            ProcessTlsInformation, // PROCESS_TLS_INFORMATION // ProcessResourceManagement
            ProcessCookie, // q: ULONG
            ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
            ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
            ProcessPagePriority, // qs: PAGE_PRIORITY_INFORMATION
            ProcessInstrumentationCallback, // s: PVOID or PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION // 40
            ProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
            ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]
            ProcessImageFileNameWin32, // q: UNICODE_STRING
            ProcessImageFileMapping, // q: HANDLE (input)
            ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
            ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
            ProcessGroupInformation, // q: USHORT[]
            ProcessTokenVirtualizationEnabled, // s: ULONG
            ProcessConsoleHostProcess, // qs: ULONG_PTR // ProcessOwnerInformation
            ProcessWindowInformation, // q: PROCESS_WINDOW_INFORMATION // 50
            ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
            ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
            ProcessDynamicFunctionTableInformation,
            ProcessHandleCheckingMode, // qs: ULONG; s: 0 disables, otherwise enables
            ProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
            ProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
            ProcessWorkingSetControl, // s: PROCESS_WORKING_SET_CONTROL
            ProcessHandleTable, // q: ULONG[] // since WINBLUE
            ProcessCheckStackExtentsMode, // qs: ULONG // KPROCESS->CheckStackExtents (CFG)
            ProcessCommandLineInformation, // q: UNICODE_STRING // 60
            ProcessProtectionInformation, // q: PS_PROTECTION
            ProcessMemoryExhaustion, // PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
            ProcessFaultInformation, // PROCESS_FAULT_INFORMATION
            ProcessTelemetryIdInformation, // q: PROCESS_TELEMETRY_ID_INFORMATION
            ProcessCommitReleaseInformation, // PROCESS_COMMIT_RELEASE_INFORMATION
            ProcessDefaultCpuSetsInformation, // SYSTEM_CPU_SET_INFORMATION[5]
            ProcessAllowedCpuSetsInformation, // SYSTEM_CPU_SET_INFORMATION[5]
            ProcessSubsystemProcess,
            ProcessJobMemoryInformation, // q: PROCESS_JOB_MEMORY_INFO
            ProcessInPrivate, // s: void // ETW // since THRESHOLD2 // 70
            ProcessRaiseUMExceptionOnInvalidHandleClose, // qs: ULONG; s: 0 disables, otherwise enables
            ProcessIumChallengeResponse,
            ProcessChildProcessInformation, // q: PROCESS_CHILD_PROCESS_INFORMATION
            ProcessHighGraphicsPriorityInformation, // qs: BOOLEAN (requires SeTcbPrivilege)
            ProcessSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
            ProcessEnergyValues, // q: PROCESS_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES
            ProcessPowerThrottlingState, // qs: POWER_THROTTLING_PROCESS_STATE
            ProcessReserved3Information, // ProcessActivityThrottlePolicy // PROCESS_ACTIVITY_THROTTLE_POLICY
            ProcessWin32kSyscallFilterInformation, // q: WIN32K_SYSCALL_FILTER
            ProcessDisableSystemAllowedCpuSets, // 80
            ProcessWakeInformation, // PROCESS_WAKE_INFORMATION
            ProcessEnergyTrackingState, // PROCESS_ENERGY_TRACKING_STATE
            ProcessManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
            ProcessCaptureTrustletLiveDump,
            ProcessTelemetryCoverage,
            ProcessEnclaveInformation,
            ProcessEnableReadWriteVmLogging, // PROCESS_READWRITEVM_LOGGING_INFORMATION
            ProcessUptimeInformation, // q: PROCESS_UPTIME_INFORMATION
            ProcessImageSection, // q: HANDLE
            ProcessDebugAuthInformation, // since REDSTONE4 // 90
            ProcessSystemResourceManagement, // PROCESS_SYSTEM_RESOURCE_MANAGEMENT
            ProcessSequenceNumber, // q: ULONGLONG
            ProcessLoaderDetour, // since REDSTONE5
            ProcessSecurityDomainInformation, // PROCESS_SECURITY_DOMAIN_INFORMATION
            ProcessCombineSecurityDomainsInformation, // PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION
            ProcessEnableLogging, // PROCESS_LOGGING_INFORMATION
            ProcessLeapSecondInformation, // PROCESS_LEAP_SECOND_INFORMATION
            ProcessFiberShadowStackAllocation, // PROCESS_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION // since 19H1
            ProcessFreeFiberShadowStackAllocation, // PROCESS_FREE_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION
            ProcessAltSystemCallInformation, // qs: BOOLEAN (kernel-mode only) // INT2E // since 20H1 // 100
            ProcessDynamicEHContinuationTargets, // PROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION
            ProcessDynamicEnforcedCetCompatibleRanges, // PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE_INFORMATION // since 20H2
            ProcessCreateStateChange, // since WIN11
            ProcessApplyStateChange,
            ProcessEnableOptionalXStateFeatures,
            ProcessAltPrefetchParam, // since 22H1
            ProcessAssignCpuPartitions,
            ProcessPriorityClassEx, // s: PROCESS_PRIORITY_CLASS_EX
            ProcessMembershipInformation,
            ProcessEffectiveIoPriority, // q: IO_PRIORITY_HINT
            ProcessEffectivePagePriority, // q: ULONG
            MaxProcessInfoClass
        }


        [Flags]
        public enum SectionFlags : uint
        {
            TYPE_NO_PAD = 0x00000008,
            CNT_CODE = 0x00000020,
            CNT_INITIALIZED_DATA = 0x00000040,
            CNT_UNINITIALIZED_DATA = 0x00000080,
            LNK_INFO = 0x00000200,
            LNK_REMOVE = 0x00000800,
            LNK_COMDAT = 0x00001000,
            NO_DEFER_SPEC_EXC = 0x00004000,
            GPREL = 0x00008000,
            MEM_FARDATA = 0x00008000,
            MEM_PURGEABLE = 0x00020000,
            MEM_16BIT = 0x00020000,
            MEM_LOCKED = 0x00040000,
            MEM_PRELOAD = 0x00080000,
            ALIGN_1BYTES = 0x00100000,
            ALIGN_2BYTES = 0x00200000,
            ALIGN_4BYTES = 0x00300000,
            ALIGN_8BYTES = 0x00400000,
            ALIGN_16BYTES = 0x00500000,
            ALIGN_32BYTES = 0x00600000,
            ALIGN_64BYTES = 0x00700000,
            ALIGN_128BYTES = 0x00800000,
            ALIGN_256BYTES = 0x00900000,
            ALIGN_512BYTES = 0x00A00000,
            ALIGN_1024BYTES = 0x00B00000,
            ALIGN_2048BYTES = 0x00C00000,
            ALIGN_4096BYTES = 0x00D00000,
            ALIGN_8192BYTES = 0x00E00000,
            ALIGN_MASK = 0x00F00000,
            LNK_NRELOC_OVFL = 0x01000000,
            MEM_DISCARDABLE = 0x02000000,
            MEM_NOT_CACHED = 0x04000000,
            MEM_NOT_PAGED = 0x08000000,
            MEM_SHARED = 0x10000000,
            MEM_EXECUTE = 0x20000000,
            MEM_READ = 0x40000000,
            MEM_WRITE = 0x80000000
        }

        public enum StateEnum : uint
        {
            MEM_COMMIT = 0x1000,
            MEM_FREE = 0x10000,
            MEM_RESERVE = 0x2000
        }

        public enum SubSystemType : ushort
        {
            IMAGE_SUBSYSTEM_UNKNOWN = 0,
            IMAGE_SUBSYSTEM_NATIVE = 1,
            IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
            IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
            IMAGE_SUBSYSTEM_POSIX_CUI = 7,
            IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
            IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
            IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
            IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
            IMAGE_SUBSYSTEM_EFI_ROM = 13,
            IMAGE_SUBSYSTEM_XBOX = 14
        }

        public enum TypeEnum : uint
        {
            MEM_IMAGE = 0x1000000,
            MEM_MAPPED = 0x40000,
            MEM_PRIVATE = 0x20000
        }

        #endregion

        #region Struct

        /*
         * P/Invoke : Structs
         */
        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public uint VirtualAddress;
            public uint Size;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DOS_HEADER
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public char[] e_magic;    // Magic number
            public ushort e_cblp;     // Bytes on last page of file
            public ushort e_cp;       // Pages in file
            public ushort e_crlc;     // Relocations
            public ushort e_cparhdr;  // Size of header in paragraphs
            public ushort e_minalloc; // Minimum extra paragraphs needed
            public ushort e_maxalloc; // Maximum extra paragraphs needed
            public ushort e_ss;       // Initial (relative) SS value
            public ushort e_sp;       // Initial SP value
            public ushort e_csum;     // Checksum
            public ushort e_ip;       // Initial IP value
            public ushort e_cs;       // Initial (relative) CS value
            public ushort e_lfarlc;   // File address of relocation table
            public ushort e_ovno;     // Overlay number
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public ushort[] e_res1;   // Reserved words
            public ushort e_oemid;    // OEM identifier (for e_oeminfo)
            public ushort e_oeminfo;  // OEM information; e_oemid specific
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public ushort[] e_res2;   // Reserved words
            public int e_lfanew;      // File address of new exe header

            private string GetMagic
            {
                get { return new string(e_magic); }
            }

            public bool IsValid
            {
                get { return GetMagic == "MZ"; }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_EXPORT_DIRECTORY
        {
            public uint Characteristics;
            public uint TimeDateStamp;
            public ushort MajorVersion;
            public ushort MinorVersion;
            public uint Name;
            public uint Base;
            public uint NumberOfFunctions;
            public uint NumberOfNames;
            public uint AddressOfFunctions;
            public uint AddressOfNames;
            public uint AddressOfNameOrdinals;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_FILE_HEADER
        {
            public ushort Machine;
            public ushort NumberOfSections;
            public uint TimeDateStamp;
            public uint PointerToSymbolTable;
            public uint NumberOfSymbols;
            public ushort SizeOfOptionalHeader;
            public ushort Characteristics;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_OPTIONAL_HEADER32
        {
            [FieldOffset(0)]
            public MagicType Magic;

            [FieldOffset(2)]
            public byte MajorLinkerVersion;

            [FieldOffset(3)]
            public byte MinorLinkerVersion;

            [FieldOffset(4)]
            public uint SizeOfCode;

            [FieldOffset(8)]
            public uint SizeOfInitializedData;

            [FieldOffset(12)]
            public uint SizeOfUninitializedData;

            [FieldOffset(16)]
            public uint AddressOfEntryPoint;

            [FieldOffset(20)]
            public uint BaseOfCode;

            // PE32 contains this additional field
            [FieldOffset(24)]
            public uint BaseOfData;

            [FieldOffset(28)]
            public uint ImageBase;

            [FieldOffset(32)]
            public uint SectionAlignment;

            [FieldOffset(36)]
            public uint FileAlignment;

            [FieldOffset(40)]
            public ushort MajorOperatingSystemVersion;

            [FieldOffset(42)]
            public ushort MinorOperatingSystemVersion;

            [FieldOffset(44)]
            public ushort MajorImageVersion;

            [FieldOffset(46)]
            public ushort MinorImageVersion;

            [FieldOffset(48)]
            public ushort MajorSubsystemVersion;

            [FieldOffset(50)]
            public ushort MinorSubsystemVersion;

            [FieldOffset(52)]
            public uint Win32VersionValue;

            [FieldOffset(56)]
            public uint SizeOfImage;

            [FieldOffset(60)]
            public uint SizeOfHeaders;

            [FieldOffset(64)]
            public uint CheckSum;

            [FieldOffset(68)]
            public SubSystemType Subsystem;

            [FieldOffset(70)]
            public DllCharacteristicsType DllCharacteristics;

            [FieldOffset(72)]
            public uint SizeOfStackReserve;

            [FieldOffset(76)]
            public uint SizeOfStackCommit;

            [FieldOffset(80)]
            public uint SizeOfHeapReserve;

            [FieldOffset(84)]
            public uint SizeOfHeapCommit;

            [FieldOffset(88)]
            public uint LoaderFlags;

            [FieldOffset(92)]
            public uint NumberOfRvaAndSizes;

            [FieldOffset(96)]
            public IMAGE_DATA_DIRECTORY ExportTable;

            [FieldOffset(104)]
            public IMAGE_DATA_DIRECTORY ImportTable;

            [FieldOffset(112)]
            public IMAGE_DATA_DIRECTORY ResourceTable;

            [FieldOffset(120)]
            public IMAGE_DATA_DIRECTORY ExceptionTable;

            [FieldOffset(128)]
            public IMAGE_DATA_DIRECTORY CertificateTable;

            [FieldOffset(136)]
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;

            [FieldOffset(144)]
            public IMAGE_DATA_DIRECTORY Debug;

            [FieldOffset(152)]
            public IMAGE_DATA_DIRECTORY Architecture;

            [FieldOffset(160)]
            public IMAGE_DATA_DIRECTORY GlobalPtr;

            [FieldOffset(168)]
            public IMAGE_DATA_DIRECTORY TLSTable;

            [FieldOffset(176)]
            public IMAGE_DATA_DIRECTORY LoadConfigTable;

            [FieldOffset(184)]
            public IMAGE_DATA_DIRECTORY BoundImport;

            [FieldOffset(192)]
            public IMAGE_DATA_DIRECTORY IAT;

            [FieldOffset(200)]
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;

            [FieldOffset(208)]
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

            [FieldOffset(216)]
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_OPTIONAL_HEADER64
        {
            [FieldOffset(0)]
            public MagicType Magic;

            [FieldOffset(2)]
            public byte MajorLinkerVersion;

            [FieldOffset(3)]
            public byte MinorLinkerVersion;

            [FieldOffset(4)]
            public uint SizeOfCode;

            [FieldOffset(8)]
            public uint SizeOfInitializedData;

            [FieldOffset(12)]
            public uint SizeOfUninitializedData;

            [FieldOffset(16)]
            public uint AddressOfEntryPoint;

            [FieldOffset(20)]
            public uint BaseOfCode;

            [FieldOffset(24)]
            public ulong ImageBase;

            [FieldOffset(32)]
            public uint SectionAlignment;

            [FieldOffset(36)]
            public uint FileAlignment;

            [FieldOffset(40)]
            public ushort MajorOperatingSystemVersion;

            [FieldOffset(42)]
            public ushort MinorOperatingSystemVersion;

            [FieldOffset(44)]
            public ushort MajorImageVersion;

            [FieldOffset(46)]
            public ushort MinorImageVersion;

            [FieldOffset(48)]
            public ushort MajorSubsystemVersion;

            [FieldOffset(50)]
            public ushort MinorSubsystemVersion;

            [FieldOffset(52)]
            public uint Win32VersionValue;

            [FieldOffset(56)]
            public uint SizeOfImage;

            [FieldOffset(60)]
            public uint SizeOfHeaders;

            [FieldOffset(64)]
            public uint CheckSum;

            [FieldOffset(68)]
            public SubSystemType Subsystem;

            [FieldOffset(70)]
            public DllCharacteristicsType DllCharacteristics;

            [FieldOffset(72)]
            public ulong SizeOfStackReserve;

            [FieldOffset(80)]
            public ulong SizeOfStackCommit;

            [FieldOffset(88)]
            public ulong SizeOfHeapReserve;

            [FieldOffset(96)]
            public ulong SizeOfHeapCommit;

            [FieldOffset(104)]
            public uint LoaderFlags;

            [FieldOffset(108)]
            public uint NumberOfRvaAndSizes;

            [FieldOffset(112)]
            public IMAGE_DATA_DIRECTORY ExportTable;

            [FieldOffset(120)]
            public IMAGE_DATA_DIRECTORY ImportTable;

            [FieldOffset(128)]
            public IMAGE_DATA_DIRECTORY ResourceTable;

            [FieldOffset(136)]
            public IMAGE_DATA_DIRECTORY ExceptionTable;

            [FieldOffset(144)]
            public IMAGE_DATA_DIRECTORY CertificateTable;

            [FieldOffset(152)]
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;

            [FieldOffset(160)]
            public IMAGE_DATA_DIRECTORY Debug;

            [FieldOffset(168)]
            public IMAGE_DATA_DIRECTORY Architecture;

            [FieldOffset(176)]
            public IMAGE_DATA_DIRECTORY GlobalPtr;

            [FieldOffset(184)]
            public IMAGE_DATA_DIRECTORY TLSTable;

            [FieldOffset(192)]
            public IMAGE_DATA_DIRECTORY LoadConfigTable;

            [FieldOffset(200)]
            public IMAGE_DATA_DIRECTORY BoundImport;

            [FieldOffset(208)]
            public IMAGE_DATA_DIRECTORY IAT;

            [FieldOffset(216)]
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;

            [FieldOffset(224)]
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

            [FieldOffset(232)]
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct IMAGE_NT_HEADERS32
        {
            public int Signature;
            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER32 OptionalHeader;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct IMAGE_NT_HEADERS64
        {
            public int Signature;
            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_SECTION_HEADER
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 8)]
            public string Name;
            public uint VirtualSize;
            public uint VirtualAddress;
            public uint SizeOfRawData;
            public uint PointerToRawData;
            public uint PointerToRelocations;
            public uint PointerToLinenumbers;
            public ushort NumberOfRelocations;
            public ushort NumberOfLinenumbers;
            public SectionFlags Characteristics;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public AllocationProtectEnum AllocationProtect;
            public IntPtr RegionSize;
            public StateEnum State;
            public AllocationProtectEnum Protect;
            public TypeEnum Type;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr ExitStatus;
            public IntPtr PebAddress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public IntPtr UniquePID;
            public IntPtr InheritedFromUniqueProcessId;
        }

        #endregion

        /*
         * P/Invoke : Functions
         */
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool IsWow64Process(
            IntPtr hProcess,
            out bool Wow64Process);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr LocalAlloc(
            LocalMemoryFlags uFlags,
            uint uBytes);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            IntPtr lpBuffer,
            uint nSize,
            IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int VirtualQueryEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            out MEMORY_BASIC_INFORMATION lpBuffer,
            uint dwLength);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern int NtQueryInformationProcess(
            IntPtr processHandle,
            PROCESSINFOCLASS processInformationClass,
            IntPtr processInformation,
            uint processInformationLength,
            IntPtr returnLength);

        /*
         * Global Variables
         */
        private readonly bool IsRemote;
        private readonly IntPtr hProcess;
        private readonly IntPtr Peb;
        private readonly Process g_Process;
        private readonly string ProcessName;
        private readonly int ProcessId;
        private string CurrentModule;
        private IntPtr ImageBase;
        private readonly string Architecture;
        private IMAGE_DOS_HEADER DosHeader;
        private IMAGE_NT_HEADERS32 NtHeader32;
        private IMAGE_NT_HEADERS64 NtHeader64;
        private List<IMAGE_SECTION_HEADER> SectionHeaders;
        public Dictionary<string, IntPtr> Modules;

        /*
         * Constructors
         */
        public PeProcess()
        {
            this.IsRemote = false;

            this.g_Process = Process.GetCurrentProcess();
            this.hProcess = this.g_Process.Handle;
            this.CurrentModule = this.g_Process.ProcessName;

            if (!this.CurrentModule.EndsWith(".exe"))
                this.CurrentModule = string.Format("{0}.exe", this.CurrentModule);

            this.ProcessName = this.CurrentModule;
            this.ProcessId = this.g_Process.Id;

            foreach (ProcessModule mod in this.g_Process.Modules)
            {
                if (string.Compare(
                    Path.GetFileName(mod.ModuleName),
                    this.CurrentModule,
                    StringComparison.OrdinalIgnoreCase) == 0)
                {
                    this.ImageBase = mod.BaseAddress;
                    break;
                }
            }

            if (this.ImageBase == IntPtr.Zero)
                throw new KeyNotFoundException(string.Format(
                    "Image base of {0} is not found",
                    this.CurrentModule));

            this.DosHeader = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(
                this.ImageBase,
                typeof(IMAGE_DOS_HEADER));

            var lpNtHeader = new IntPtr(this.ImageBase.ToInt64() + this.DosHeader.e_lfanew);
            var arch = (ushort)this.ReadInt16(lpNtHeader, (uint)Marshal.SizeOf(typeof(int)));

            if (arch == 0x8664 || arch == 0x014C)
            {
                this.NtHeader32 = (IMAGE_NT_HEADERS32)Marshal.PtrToStructure(
                    lpNtHeader,
                    typeof(IMAGE_NT_HEADERS32));
                this.NtHeader64 = (IMAGE_NT_HEADERS64)Marshal.PtrToStructure(
                    lpNtHeader,
                    typeof(IMAGE_NT_HEADERS64));
            }
            else
            {
                throw new ArgumentException(string.Format(
                    "{0} (PID: {1}) is not supported architecture",
                    this.CurrentModule,
                    this.ProcessId));
            }

            this.Architecture = Environment.Is64BitProcess ? "x64" : "x86";
            this.SectionHeaders = this.GetSectionHeaders();

            if (this.SectionHeaders.Count == 0)
                throw new ArgumentException(string.Format(
                    "{0} (PID: {1}) has no section headers.",
                    this.CurrentModule,
                    this.ProcessId));

            this.Peb = this.ResolvePebAddress();

            if (this.Peb == IntPtr.Zero)
                throw new Win32Exception(string.Format(
                    "Failed to find PEB for {0} (PID: {1}).",
                    this.CurrentModule,
                    this.ProcessId));

            this.Modules = ResolveModuleBases();

            if (this.Modules.Count == 0)
                throw new ArgumentException(string.Format(
                    "{0} (PID: {1}) has no modules.",
                    this.CurrentModule,
                    this.ProcessId));
        }

        public PeProcess(int pid)
        {
            this.IsRemote = true;

            this.g_Process = Process.GetProcessById(pid);
            this.hProcess = this.g_Process.Handle;
            this.CurrentModule = this.g_Process.ProcessName;

            if (!this.CurrentModule.EndsWith(".exe"))
                this.CurrentModule = string.Format("{0}.exe", this.CurrentModule);

            this.ProcessName = this.CurrentModule;
            this.ProcessId = this.g_Process.Id;

            foreach (ProcessModule mod in this.g_Process.Modules)
            {
                if (string.Compare(
                    Path.GetFileName(mod.ModuleName),
                    this.CurrentModule,
                    StringComparison.OrdinalIgnoreCase) == 0)
                {
                    this.ImageBase = mod.BaseAddress;
                    break;
                }
            }

            if (this.ImageBase == IntPtr.Zero)
                throw new KeyNotFoundException(string.Format(
                    "Image base of {0} is not found.",
                    this.CurrentModule));

            var sizeDosHeader = (uint)Marshal.SizeOf(typeof(IMAGE_DOS_HEADER));
            var buffer = this.ReadMemory(this.ImageBase, (uint)sizeDosHeader);
            this.DosHeader = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(
                buffer,
                typeof(IMAGE_DOS_HEADER));
            LocalFree(buffer);

            uint sizeNtHeader;
            var lpNtHeader = new IntPtr(this.ImageBase.ToInt64() + this.DosHeader.e_lfanew);
            var arch = (ushort)this.ReadInt16(lpNtHeader, (uint)Marshal.SizeOf(typeof(int)));

            if (arch == 0x8664)
            {
                this.Architecture = "x64";
                sizeNtHeader = (uint)Marshal.SizeOf(typeof(IMAGE_NT_HEADERS64));
                buffer = this.ReadMemory(lpNtHeader, sizeNtHeader);

                this.NtHeader32 = new IMAGE_NT_HEADERS32();
                this.NtHeader64 = (IMAGE_NT_HEADERS64)Marshal.PtrToStructure(
                    buffer,
                    typeof(IMAGE_NT_HEADERS64));

                LocalFree(buffer);
            }
            else if (arch == 0x014C)
            {
                this.Architecture = "x86";
                sizeNtHeader = (uint)Marshal.SizeOf(typeof(IMAGE_NT_HEADERS32));
                buffer = this.ReadMemory(lpNtHeader, sizeNtHeader);

                this.NtHeader32 = (IMAGE_NT_HEADERS32)Marshal.PtrToStructure(
                    buffer,
                    typeof(IMAGE_NT_HEADERS32));
                this.NtHeader64 = new IMAGE_NT_HEADERS64();

                LocalFree(buffer);
            }
            else
            {
                throw new ArgumentException(string.Format(
                    "{0} (PID: {1}) is not supported architecture.",
                    this.CurrentModule,
                    this.ProcessId));
            }

            if (Environment.Is64BitOperatingSystem)
            {
                IsWow64Process(hProcess, out bool Wow64Process);

                this.Architecture = Wow64Process ? "x86" : "x64";
            }

            this.SectionHeaders = this.GetSectionHeaders();

            if (this.SectionHeaders.Count == 0)
                throw new ArgumentException(string.Format(
                    "{0} (PID: {1}) has no section headers.",
                    this.CurrentModule,
                    this.ProcessId));

            this.Peb = this.ResolvePebAddress();

            if (this.Peb == IntPtr.Zero)
                throw new Win32Exception(string.Format(
                    "Failed to find PEB for {0} (PID: {1}).",
                    this.CurrentModule,
                    this.ProcessId));

            this.Modules = ResolveModuleBases();

            if (this.Modules.Count == 0)
                throw new ArgumentException(string.Format(
                    "{0} (PID: {1}) has no modules.",
                    this.CurrentModule,
                    this.ProcessId));
        }


        /*
         * Destructor
         */
        public void Dispose()
        {
            this.g_Process.Dispose();
        }


        /*
         * Class Methods
         */
        public string GetArchitecture()
        {
            return this.Architecture;
        }


        public string GetCurrentModuleName()
        {
            return this.CurrentModule;
        }


        public long GetHeapSize(IntPtr address)
        {
            int ret;
            int size;

            if (address == IntPtr.Zero)
                return 0L;

            size = Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));

            ret = VirtualQueryEx(
                hProcess,
                address,
                out MEMORY_BASIC_INFORMATION mbi,
                (uint)size);

            if (ret != size)
                return 0L;

            return mbi.RegionSize.ToInt64();
        }


        public IntPtr GetModuleBase(string moduleName)
        {
            if (this.Modules.ContainsKey(moduleName))
                return this.Modules[moduleName];
            else
                return IntPtr.Zero;
        }


        public IntPtr GetImageBase()
        {
            return this.ImageBase;
        }


        public IntPtr GetSectionAddress(string sectionName)
        {
            foreach (var entry in this.SectionHeaders)
            {
                if (string.Compare(
                    entry.Name,
                    sectionName,
                    StringComparison.OrdinalIgnoreCase) == 0)
                {
                    return new IntPtr(this.ImageBase.ToInt64() + entry.VirtualAddress);
                }
            }

            throw new KeyNotFoundException(string.Format(
                "{0} section is not found",
                sectionName));
        }


        public IntPtr GetPebAddress()
        {
            return Peb;
        }


        public IntPtr GetProcessHandle()
        {
            return hProcess;
        }


        public int GetProcessId()
        {
            return this.ProcessId;
        }


        public string GetProcessName()
        {
            return this.ProcessName;
        }


        private List<IMAGE_SECTION_HEADER> GetSectionHeaders()
        {
            var sectionHeaders = new List<IMAGE_SECTION_HEADER>();
            IMAGE_SECTION_HEADER sectionHeader;
            var nSectionHeaderSize = (uint)Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER));
            IntPtr pSectionHeaders;
            ushort nSectionCount;
            IntPtr buffer;

            if (this.Architecture == "x64")
            {
                nSectionCount = this.NtHeader64.FileHeader.NumberOfSections;
                pSectionHeaders = new IntPtr(
                    this.ImageBase.ToInt64() +
                    this.DosHeader.e_lfanew +
                    0x18 +
                    this.NtHeader64.FileHeader.SizeOfOptionalHeader);

                for (var idx = 0; idx < nSectionCount; idx++)
                {
                    if (this.IsRemote)
                    {
                        buffer = this.ReadMemory(
                            new IntPtr(pSectionHeaders.ToInt64() + idx * nSectionHeaderSize),
                            nSectionHeaderSize);
                        sectionHeader = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure(
                            buffer,
                            typeof(IMAGE_SECTION_HEADER));
                        LocalFree(buffer);
                        sectionHeaders.Add(sectionHeader);
                    }
                    else
                    {
                        sectionHeader = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure(
                            new IntPtr(pSectionHeaders.ToInt64() + idx * nSectionHeaderSize),
                            typeof(IMAGE_SECTION_HEADER));
                        sectionHeaders.Add(sectionHeader);
                    }
                }
            }
            else if (this.Architecture == "x86")
            {
                nSectionCount = this.NtHeader32.FileHeader.NumberOfSections;
                pSectionHeaders = new IntPtr(
                    this.ImageBase.ToInt64() +
                    this.DosHeader.e_lfanew +
                    0x18 +
                    this.NtHeader32.FileHeader.SizeOfOptionalHeader);

                for (var idx = 0; idx < nSectionCount; idx++)
                {
                    if (this.IsRemote)
                    {
                        buffer = this.ReadMemory(
                            new IntPtr(pSectionHeaders.ToInt64() + idx * nSectionHeaderSize),
                            nSectionHeaderSize);
                        sectionHeader = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure(
                            buffer,
                            typeof(IMAGE_SECTION_HEADER));
                        LocalFree(buffer);
                        sectionHeaders.Add(sectionHeader);
                    }
                    else
                    {
                        sectionHeader = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure(
                            new IntPtr(pSectionHeaders.ToInt64() + idx * nSectionHeaderSize),
                            typeof(IMAGE_SECTION_HEADER));
                        sectionHeaders.Add(sectionHeader);
                    }
                }
            }

            return sectionHeaders;
        }


        public uint GetSectionVirtualSize(string sectionName)
        {
            foreach (var entry in this.SectionHeaders)
            {
                if (string.Compare(
                    entry.Name,
                    sectionName,
                    StringComparison.OrdinalIgnoreCase) == 0)
                {
                    return entry.VirtualSize;
                }
            }

            return 0u;
        }


        public bool IsHeapAddress(IntPtr address)
        {
            int ret;
            int size;

            if (address == IntPtr.Zero)
                return false;

            size = Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));

            ret = VirtualQueryEx(
                hProcess,
                address,
                out MEMORY_BASIC_INFORMATION mbi,
                (uint)size);

            if (ret != size)
                return false;

            return (mbi.State == StateEnum.MEM_COMMIT) &&
                (mbi.Type == TypeEnum.MEM_PRIVATE) &&
                (mbi.Protect == AllocationProtectEnum.PAGE_READWRITE);
        }


        public string[] ListModuleNames()
        {
            var results = new List<string>();

            foreach (ProcessModule mod in this.g_Process.Modules)
                results.Add(mod.ModuleName);

            return results.ToArray();
        }


        public string[] ListSectionNames()
        {
            var results = new List<string>();

            foreach (var entry in this.SectionHeaders)
                results.Add(entry.Name);

            return results.ToArray();
        }


        public string ReadAnsiString(IntPtr address)
        {
            IntPtr buffer;
            uint counter = 0;
            byte tmp;
            string result;

            while (true)
            {
                tmp = this.ReadByte(address, counter);
                counter++;

                if (tmp == (byte)0)
                    break;
            }

            buffer = this.ReadMemory(address, counter);

            if (buffer == IntPtr.Zero)
                return null;

            result = Marshal.PtrToStringAnsi(buffer);
            LocalFree(buffer);

            return result;
        }


        public string ReadAnsiString(IntPtr address, uint offset)
        {
            IntPtr buffer;
            uint counter = 0;
            byte tmp;
            string result;
            address = new IntPtr(address.ToInt64() + offset);

            while (true)
            {
                tmp = this.ReadByte(address, counter);
                counter++;

                if (tmp == (byte)0)
                    break;
            }

            buffer = this.ReadMemory(address, counter);

            if (buffer == IntPtr.Zero)
                return null;

            result = Marshal.PtrToStringAnsi(buffer);
            LocalFree(buffer);

            return result;
        }


        public byte ReadByte(IntPtr address)
        {
            IntPtr buffer = this.ReadMemory(address, 1u);
            byte result = Marshal.ReadByte(buffer);
            LocalFree(buffer);

            return result;
        }


        public byte ReadByte(IntPtr address, uint offset)
        {
            IntPtr buffer = this.ReadMemory(address, offset, 1u);
            byte result = Marshal.ReadByte(buffer);
            LocalFree(buffer);

            return result;
        }


        public short ReadInt16(IntPtr address)
        {
            IntPtr buffer = this.ReadMemory(address, 2u);
            short result = Marshal.ReadInt16(buffer);
            LocalFree(buffer);

            return result;
        }


        public short ReadInt16(IntPtr address, uint offset)
        {
            IntPtr buffer = this.ReadMemory(address, offset, 2u);
            short result = Marshal.ReadInt16(buffer);
            LocalFree(buffer);

            return result;
        }


        public int ReadInt32(IntPtr address)
        {
            IntPtr buffer = this.ReadMemory(address, 4u);
            int result = Marshal.ReadInt32(buffer);
            LocalFree(buffer);

            return result;
        }


        public int ReadInt32(IntPtr address, uint offset)
        {
            IntPtr buffer = this.ReadMemory(address, offset, 4u);
            int result = Marshal.ReadInt32(buffer);
            LocalFree(buffer);

            return result;
        }


        public long ReadInt64(IntPtr address)
        {
            IntPtr buffer = this.ReadMemory(address, 8u);
            long result = Marshal.ReadInt64(buffer);
            LocalFree(buffer);

            return result;
        }


        public long ReadInt64(IntPtr address, uint offset)
        {
            IntPtr buffer = this.ReadMemory(address, offset, 8u);
            long result = Marshal.ReadInt64(buffer);
            LocalFree(buffer);

            return result;
        }


        public IntPtr ReadIntPtr(IntPtr address)
        {
            if (this.Architecture == "x64")
                return new IntPtr(this.ReadInt64(address));
            else if (this.Architecture == "x86")
                return new IntPtr(this.ReadInt32(address));
            else
                return IntPtr.Zero;
        }


        public IntPtr ReadIntPtr(IntPtr address, uint offset)
        {
            if (this.Architecture == "x64")
                return new IntPtr(this.ReadInt64(address, offset));
            else if (this.Architecture == "x86")
                return new IntPtr(this.ReadInt32(address, offset));
            else
                return IntPtr.Zero;
        }


        public IntPtr ReadMemory(IntPtr address, uint size)
        {
            IntPtr buffer = LocalAlloc(
                LocalMemoryFlags.LMEM_FIXED | LocalMemoryFlags.LMEM_ZEROINIT,
                size);

            if (!ReadProcessMemory(
                this.hProcess,
                address,
                buffer,
                size,
                IntPtr.Zero))
            {
                LocalFree(buffer);

                return IntPtr.Zero;
            }

            return buffer;
        }


        public IntPtr ReadMemory(IntPtr address, uint offset, uint size)
        {
            IntPtr buffer = LocalAlloc(
                LocalMemoryFlags.LMEM_FIXED | LocalMemoryFlags.LMEM_ZEROINIT,
                size);
            address = new IntPtr(address.ToInt64() + offset);

            if (!ReadProcessMemory(
                this.hProcess,
                address,
                buffer,
                size,
                IntPtr.Zero))
            {
                LocalFree(buffer);

                return IntPtr.Zero;
            }

            return buffer;
        }


        public string ReadUnicodeString(IntPtr address)
        {
            IntPtr buffer;
            uint counter = 0u;
            short tmp;
            string result;

            while (true)
            {
                tmp = this.ReadInt16(address, counter);
                counter += 2;

                if (tmp == (short)0)
                    break;
            }

            buffer = this.ReadMemory(address, counter);

            if (buffer == IntPtr.Zero)
                return null;

            result = Marshal.PtrToStringUni(buffer);
            LocalFree(buffer);

            return result;
        }


        public string ReadUnicodeString(IntPtr address, uint offset)
        {
            IntPtr buffer;
            uint counter = 0u;
            short tmp;
            string result;
            address = new IntPtr(address.ToInt64() + offset);

            while (true)
            {
                tmp = this.ReadInt16(address, counter);
                counter += 2;

                if (tmp == (short)0)
                    break;
            }

            buffer = this.ReadMemory(address, counter);

            if (buffer == IntPtr.Zero)
                return null;

            result = Marshal.PtrToStringUni(buffer);
            LocalFree(buffer);

            return result;
        }

        public bool WriteBytes(IntPtr address, byte[] buffer)
        {
            IntPtr lpNumberOfBytesWritten = IntPtr.Zero;
            return NativeAPI.WriteProcessMemory(this.hProcess, address, buffer, (uint)buffer.Length, out lpNumberOfBytesWritten);
        }

        public bool WriteBytes(IntPtr address, IntPtr buffer, uint nSize)
        {
            IntPtr lpNumberOfBytesWritten = IntPtr.Zero;
            return NativeAPI.WriteProcessMemory(this.hProcess, address, ref buffer, nSize, out lpNumberOfBytesWritten);
        }


        public Dictionary<string, IntPtr> ResolveModuleBases()
        {
            var result = new Dictionary<string, IntPtr>();
            string moduleName;
            IntPtr moduleBase;

            if (this.Architecture == "x86" && Environment.Is64BitOperatingSystem)
            {
                if (this.Peb == IntPtr.Zero)
                    return result;

                var pLdr = this.ReadIntPtr(this.Peb, 0x0C);
                // _LDR_DATA_TABLE_ENTRY
                var pInLoadOrderModuleList = this.ReadIntPtr(pLdr, 0x0C);
                IntPtr pModuleName;

                while (true)
                {
                    pModuleName = this.ReadIntPtr(pInLoadOrderModuleList, 0x30);

                    if (pModuleName == IntPtr.Zero)
                        break;

                    moduleName = this.ReadUnicodeString(pModuleName);
                    moduleBase = this.ReadIntPtr(pInLoadOrderModuleList, 0x18);

                    if (result.ContainsKey(moduleName))
                        break;
                    else
                        result.Add(moduleName, moduleBase);

                    pInLoadOrderModuleList = this.ReadIntPtr(pInLoadOrderModuleList);
                }
            }
            else
            {
                foreach (ProcessModule mod in this.g_Process.Modules)
                {
                    moduleName = Path.GetFileName(mod.ModuleName);
                    moduleBase = mod.BaseAddress;

                    if (!result.ContainsKey(moduleName))
                        result.Add(moduleName, moduleBase);
                }
            }

            return result;
        }


        private IntPtr ResolvePebAddress()
        {
            int ntstatus;
            IntPtr buffer;
            int nSize;
            PROCESS_BASIC_INFORMATION pbi;
            IntPtr peb;

            if (Environment.Is64BitProcess)
            {
                IsWow64Process(this.hProcess, out bool isWow64);

                if (isWow64)
                {
                    nSize = IntPtr.Size;
                    buffer = Marshal.AllocHGlobal(nSize);

                    ntstatus = NtQueryInformationProcess(
                        this.hProcess,
                        PROCESSINFOCLASS.ProcessWow64Information,
                        buffer,
                        (uint)nSize, IntPtr.Zero);

                    if (ntstatus == 0)
                        peb = Marshal.ReadIntPtr(buffer);
                    else
                        peb = IntPtr.Zero;

                    Marshal.FreeHGlobal(buffer);

                    return peb;
                }
            }

            nSize = Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION));
            buffer = Marshal.AllocHGlobal(nSize);

            ntstatus = NtQueryInformationProcess(
                this.hProcess,
                PROCESSINFOCLASS.ProcessBasicInformation,
                buffer,
                (uint)nSize,
                IntPtr.Zero);

            if (ntstatus == 0)
            {
                pbi = (PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(
                    buffer,
                    typeof(PROCESS_BASIC_INFORMATION));
                peb = pbi.PebAddress;
            }
            else
            {
                peb = IntPtr.Zero;
            }

            Marshal.FreeHGlobal(buffer);

            return peb;
        }


        public IntPtr[] SearchAnsiString(
            IntPtr basePointer,
            uint range,
            string searchString)
        {
            byte[] searchBytes = Encoding.ASCII.GetBytes(searchString);

            return SearchBytes(basePointer, range, searchBytes);
        }


        public IntPtr[] SearchAnsiString(
            IntPtr basePointer,
            uint offset,
            uint range,
            string searchString)
        {
            byte[] searchBytes = Encoding.ASCII.GetBytes(searchString);

            return SearchBytes(basePointer, offset, range, searchBytes);
        }


        public IntPtr[] SearchBytes(
            IntPtr basePointer,
            uint range,
            byte[] searchBytes)
        {
            var results = new List<IntPtr>();
            IntPtr pointer;
            IntPtr buffer = IntPtr.Zero;
            bool found;

            if (this.IsRemote)
            {
                buffer = ReadMemory(basePointer, range);

                if (buffer == IntPtr.Zero)
                    return results.ToArray();
            }

            for (var count = 0u; count < (range - (uint)searchBytes.Length); count++)
            {
                found = false;

                if (this.IsRemote)
                    pointer = new IntPtr(buffer.ToInt64() + count);
                else
                    pointer = new IntPtr(basePointer.ToInt64() + count);

                for (var position = 0u; position < (uint)searchBytes.Length; position++)
                {
                    found = (this.ReadByte(pointer, position) == searchBytes[position]);

                    if (!found)
                        break;
                }

                if (found && this.IsRemote)
                    results.Add(new IntPtr(basePointer.ToInt64() + count));
                else if (found && !this.IsRemote)
                    results.Add(pointer);
            }

            if (this.IsRemote)
                LocalFree(buffer);

            return results.ToArray();
        }


        public IntPtr[] SearchBytes(
            IntPtr basePointer,
            uint offset,
            uint range,
            byte[] searchBytes)
        {
            var results = new List<IntPtr>();
            IntPtr pointer;
            IntPtr buffer = IntPtr.Zero;
            bool found;

            if (this.IsRemote)
            {
                buffer = ReadMemory(basePointer, range);

                if (buffer == IntPtr.Zero)
                    return results.ToArray();
            }

            for (var count = 0u; count < (range - (uint)searchBytes.Length); count++)
            {
                found = false;

                if (this.IsRemote)
                    pointer = new IntPtr(buffer.ToInt64() + offset + count);
                else
                    pointer = new IntPtr(basePointer.ToInt64() + offset + count);

                for (var position = 0u; position < (uint)searchBytes.Length; position++)
                {
                    found = (this.ReadByte(pointer, position) == searchBytes[position]);

                    if (!found)
                        break;
                }

                if (found && this.IsRemote)
                    results.Add(new IntPtr(basePointer.ToInt64() + count));
                else if (found && !this.IsRemote)
                    results.Add(pointer);
            }

            if (this.IsRemote)
                LocalFree(buffer);

            return results.ToArray();
        }


        public IntPtr[] SearchUnicodeString(
            IntPtr basePointer,
            uint range,
            string searchString)
        {
            byte[] searchBytes = Encoding.Unicode.GetBytes(searchString);

            return SearchBytes(basePointer, range, searchBytes);
        }


        public IntPtr[] SearchUnicodeString(
            IntPtr basePointer,
            uint offset,
            uint range,
            string searchString)
        {
            byte[] searchBytes = Encoding.Unicode.GetBytes(searchString);

            return SearchBytes(basePointer, offset, range, searchBytes);
        }


        public void SetBaseModule(string moduleName)
        {
            IntPtr buffer;
            IntPtr lpNtHeader;
            IntPtr imageBase = GetModuleBase(moduleName);

            if (imageBase != IntPtr.Zero)
            {
                this.CurrentModule = moduleName;
                this.ImageBase = imageBase;

                if (this.IsRemote)
                {
                    buffer = this.ReadMemory(
                        this.ImageBase,
                        (uint)Marshal.SizeOf(typeof(IMAGE_DOS_HEADER)));
                    this.DosHeader = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(
                        buffer,
                        typeof(IMAGE_DOS_HEADER));
                    LocalFree(buffer);
                    lpNtHeader = new IntPtr(this.ImageBase.ToInt64() + this.DosHeader.e_lfanew);

                    buffer = this.ReadMemory(
                        lpNtHeader,
                        (uint)Marshal.SizeOf(typeof(IMAGE_NT_HEADERS32)));
                    this.NtHeader32 = (IMAGE_NT_HEADERS32)Marshal.PtrToStructure(
                        buffer,
                        typeof(IMAGE_NT_HEADERS32));
                    LocalFree(buffer);

                    buffer = this.ReadMemory(
                        lpNtHeader,
                        (uint)Marshal.SizeOf(typeof(IMAGE_NT_HEADERS64)));
                    this.NtHeader64 = (IMAGE_NT_HEADERS64)Marshal.PtrToStructure(
                        buffer,
                        typeof(IMAGE_NT_HEADERS64));
                    LocalFree(buffer);
                }
                else
                {
                    this.DosHeader = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(
                        this.ImageBase,
                        typeof(IMAGE_DOS_HEADER));
                    lpNtHeader = new IntPtr(this.ImageBase.ToInt64() + this.DosHeader.e_lfanew);

                    this.NtHeader32 = (IMAGE_NT_HEADERS32)Marshal.PtrToStructure(
                        lpNtHeader,
                        typeof(IMAGE_NT_HEADERS32));
                    this.NtHeader64 = (IMAGE_NT_HEADERS64)Marshal.PtrToStructure(
                        lpNtHeader,
                        typeof(IMAGE_NT_HEADERS64));
                }

                this.SectionHeaders = GetSectionHeaders();
            }
            else
            {
                throw new KeyNotFoundException(string.Format(
                    "{0} module is not found",
                    moduleName));
            }
        }
    }
}
