/*
   YARA Forensic and Threat Hunting Rules
   For zero-day and signature malware detection
*/

rule UPX_Packed {
    meta:
        description = "Detects files packed with UPX"
        severity = "Medium"
        category = "Packer"
    strings:
        $upx1 = "UPX0"
        $upx2 = "UPX1"
        $upx3 = "UPX2"
        $upx_magic = "UPX!"
    condition:
        any of ($upx*) or $upx_magic
}

rule Suspicious_Process_Injection_APIs {
    meta:
        description = "Detects Win32 APIs commonly used for code injection and process hollowing"
        severity = "High"
        category = "Injection"
    strings:
        $api1 = "VirtualAllocEx" ascii wide
        $api2 = "WriteProcessMemory" ascii wide
        $api3 = "CreateRemoteThread" ascii wide
        $api4 = "QueueUserAPC" ascii wide
        $api5 = "SetThreadContext" ascii wide
    condition:
        3 of them
}

rule Obfuscated_Powershell_Download {
    meta:
        description = "Detects obfuscated PowerShell download cradles"
        severity = "High"
        category = "Downloader"
    strings:
        $ps1 = "powershell" nocase ascii wide
        $ps2 = "-nop" nocase ascii wide
        $ps3 = "-w hidden" nocase ascii wide
        $ps4 = "DownloadString" nocase ascii wide
        $ps5 = "DownloadFile" nocase ascii wide
        $ps6 = "iex" nocase ascii wide
        $ps7 = "bypass" nocase ascii wide
    condition:
        $ps1 and (3 of ($ps2, $ps3, $ps4, $ps5, $ps6, $ps7))
}

rule Cryptographic_Stealer_Activity {
    meta:
        description = "Detects strings related to crypto wallets and browser credential harvesting"
        severity = "High"
        category = "Stealer"
    strings:
        $wallet1 = "wallet.dat" ascii wide
        $wallet2 = "Local Extension Settings" ascii wide
        $wallet3 = "Login Data" ascii wide
        $wallet4 = "Web Data" ascii wide
        $wallet5 = "Appdata\\Local\\Temp" nocase ascii wide
    condition:
        3 of them
}

rule Reverse_Shell_Strings {
    meta:
        description = "Detects reverse shell indicators"
        severity = "High"
        category = "Backdoor"
    strings:
        $sh1 = "/bin/sh" ascii wide
        $sh2 = "/bin/bash" ascii wide
        $sh3 = "cmd.exe /c" nocase ascii wide
        $sh4 = "socket.socket" ascii wide
        $sh5 = "connect((" ascii wide
        $sh6 = "WSAStartup" ascii
    condition:
        ($sh1 and $sh5) or ($sh2 and $sh5) or ($sh3 and $sh5) or ($sh4 and $sh5) or ($sh5 and $sh6)
}
