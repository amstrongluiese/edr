rule Suspicious_Encoded_Script
{
    strings:
        $a = "FromBase64String" nocase
        $b = "DownloadString" nocase
        $c = "Invoke-Expression" nocase
    condition:
        any of them
}
