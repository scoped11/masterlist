using System;
using System.IO;
using System.Runtime.InteropServices;
using Unispect;

namespace unispectDMAPlugin
{
    [UnispectPlugin("DMA Memory Plugin (MemProcFS/PciLeech)")]
    public class DMAMemoryPlugin : MemoryProxy
    {
        private IntPtr _hVMM = IntPtr.Zero;
        private uint _pid = 0;

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_Initialize")]
        private static extern IntPtr VMMDLL_Initialize(int argc, [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.LPStr)] string[] argv);

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_Close")]
        private static extern void VMMDLL_Close(IntPtr hVMM);

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_PidGetFromName")]
        private static extern bool VMMDLL_PidGetFromName(IntPtr hVMM, [MarshalAs(UnmanagedType.LPStr)] string szProcName, out uint pdwPID);

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_MemReadEx")]
        private static extern bool VMMDLL_MemReadEx(IntPtr hVMM, uint dwPID, ulong qwA, byte[] pb, uint cb, out uint pcbReadOpt, uint flags);

        [DllImport("vmm.dll", EntryPoint = "VMMDLL_Map_GetModuleFromNameU")]
        private static extern bool VMMDLL_Map_GetModuleFromNameU(IntPtr hVMM, uint dwPID, [MarshalAs(UnmanagedType.LPStr)] string uszModuleName, out IntPtr ppModuleMapEntry, uint flags);

        [StructLayout(LayoutKind.Sequential)]
        private struct VMMDLL_MAP_MODULEENTRY
        {
            public ulong vaBase;
            public ulong vaEntry;
            public uint cbImageSize;
            public bool fWoW64;
            [MarshalAs(UnmanagedType.LPStr)]
            public string uszText;
            public uint _Reserved3;
            public uint _Reserved4;
            [MarshalAs(UnmanagedType.LPStr)]
            public string uszFullName;
        }

        public override bool AttachToProcess(string handle)
        {
            try
            {
                if (_hVMM != IntPtr.Zero)
                {
                    VMMDLL_Close(_hVMM);
                    _hVMM = IntPtr.Zero;
                }

                string[] args;
                string mmapPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "mmap.txt");
                if (File.Exists(mmapPath))
                    args = new string[] { "", "-device", "fpga", "-memmap", mmapPath };
                else
                    args = new string[] { "", "-device", "fpga" };

                _hVMM = VMMDLL_Initialize(args.Length, args);
                if (_hVMM == IntPtr.Zero)
                    return false;

                if (!VMMDLL_PidGetFromName(_hVMM, handle, out _pid))
                    return false;

                return _pid > 0;
            }
            catch
            {
                return false;
            }
        }

        public override byte[] Read(ulong address, int length)
        {
            if (_hVMM == IntPtr.Zero || _pid == 0 || length <= 0)
                return null;

            byte[] buffer = new byte[length];
            uint bytesRead;
            bool ok = VMMDLL_MemReadEx(_hVMM, _pid, address, buffer, (uint)length, out bytesRead, 0x0001);
            if (!ok || bytesRead == 0)
                return null;

            return buffer;
        }

        public override ModuleProxy GetModule(string moduleName)
        {
            if (_hVMM == IntPtr.Zero || _pid == 0)
                return null;

            try
            {
                IntPtr pEntry;
                if (VMMDLL_Map_GetModuleFromNameU(_hVMM, _pid, moduleName, out pEntry, 0))
                {
                    if (pEntry != IntPtr.Zero)
                    {
                        var entry = Marshal.PtrToStructure<VMMDLL_MAP_MODULEENTRY>(pEntry);
                        return new ModuleProxy(moduleName, entry.vaBase, (int)entry.cbImageSize);
                    }
                }
            }
            catch { }

            return null;
        }

        public override void Dispose()
        {
            if (_hVMM != IntPtr.Zero)
            {
                VMMDLL_Close(_hVMM);
                _hVMM = IntPtr.Zero;
            }
        }
    }
}
