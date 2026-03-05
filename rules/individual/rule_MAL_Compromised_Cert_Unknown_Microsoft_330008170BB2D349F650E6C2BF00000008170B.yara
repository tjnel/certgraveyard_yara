import "pe"

rule MAL_Compromised_Cert_Unknown_Microsoft_330008170BB2D349F650E6C2BF00000008170B {
   meta:
      description         = "Detects Unknown with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-28"
      version             = "1.0"

      hash                = "aad8c636482191726caefd45585949710c9c2d7640670f3f2179617d53cc15a7"
      malware             = "Unknown"
      malware_type        = "Infostealer"
      malware_notes       = "First stage loader disguised as a porn game. Analysis report here: https://github.com/Squiblydoo/Remnux_Reports/blob/main/Reports%20by%20hash/635d24bff727f0efd12ecd48e6597fb75b19d786c02a090270d2310f3a7dda34_DDinosaur_analysis_report.md"

      signer              = "Ricardo Reis"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:08:17:0b:b2:d3:49:f6:50:e6:c2:bf:00:00:00:08:17:0b"
      cert_thumbprint     = "B85BEB651C3E007FE163506F2BA57994C91DD014"
      cert_valid_from     = "2026-02-28"
      cert_valid_to       = "2026-03-03"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:08:17:0b:b2:d3:49:f6:50:e6:c2:bf:00:00:00:08:17:0b"
      )
}
