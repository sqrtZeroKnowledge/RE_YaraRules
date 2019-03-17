//YaraRules Of Backdoor used PE bypass
 rule UnknownBackdoor{
  meta:
    description = "file backdoor.exe"
    author = "Touhami Kasbaoui"
    reference = "not set"
    date = "2019-03-15"
    hash = "fe5b648c3cdecad9dcd32bf6aeab2b05"
  strings:

    $hex_Mz = "4D 5A"
    $s1 = "%USERPROFILE%\source\repos\driver-process-monitor\x64\Release\WinmonProcessMonitor.pdb"
    $s2 = "79 75 77 65 2E 65  78 65 00"
    $s3 = "5F 4D 79 46 75{6E 63 31 40}34 00"
    $s4 = {C6 05 1? 44 ??}
  condition:
    $hex_Mz at 0 and
    (all of ($s*))
}
