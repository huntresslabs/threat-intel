
rule DefendNot_Hash
{
    meta:
        description = "Detects defendnot loader/dll by known hash"
        author = "Matt Anderson"
        reference = "https://github.com/es3n1n/defendnot"
    strings:
        $sha256_1 = "2e5285eee85944d0a45215dc926ba4d812523ff8" ascii /* Example SHA256 of known defendnot file */
}
rule DefendNot_KeyStrings
{
    meta:
        description = "Detects defendnot by key strings in binary"
        author = "Matt Anderson"
    strings:
        $s1 = "https://github.com/es3n1n/defendnot" wide ascii
        $s2 = "--from-autorun" ascii
        $s3 = "defendnot.dll" ascii
        $s4 = "Taskmgr.exe" ascii
        $s5 = "IWscAVStatus" ascii
    condition:
        2 of ($s*)
}

rule DefendNot_BinaryPatterns
{
    meta:
        description = "Detects defendnot by binary patterns in PE structure"
        author = "Matt Anderson"
    strings:
        $mz = { 4D 5A } // MZ header
        $repo = "defendnot" ascii
        $dll = "defendnot.dll" ascii
    condition:
        $mz at 0 and $repo and $dll
}