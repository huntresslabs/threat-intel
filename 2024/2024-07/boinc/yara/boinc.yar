rule BOINC Signature {
   meta:
      description = "Detects a signature from University of California, Berkeley, indicating it may be related to BOINC software"
      author = "Matt Anderson (Huntress)"
      reference = "https://www.virustotal.com/gui/file/91e405e8a527023fb8696624e70498ae83660fe6757cef4871ce9bcc659264d3/details"
      date = "2024-07-15"
      id = "a4d7a953-222f-4211-ac87-3d2572b6fd53"

   condition:
      pe.signatures.subject contains "University of California, Berkeley"
}