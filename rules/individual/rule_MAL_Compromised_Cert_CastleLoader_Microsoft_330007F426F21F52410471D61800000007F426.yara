import "pe"

rule MAL_Compromised_Cert_CastleLoader_Microsoft_330007F426F21F52410471D61800000007F426 {
   meta:
      description         = "Detects CastleLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-04"
      version             = "1.0"

      hash                = "6348d325ce76dc22c01ba6d3f5f4302cea960c98e196918dce098dfa12b17e4b"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = "C2 - dangeonbest[.]com"

      signer              = "Jerry Hayes"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:07:f4:26:f2:1f:52:41:04:71:d6:18:00:00:00:07:f4:26"
      cert_thumbprint     = "FD888CEAB41CFC9A7965FC9BB1F9EAD9F02D1EF4"
      cert_valid_from     = "2026-03-04"
      cert_valid_to       = "2026-03-07"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:07:f4:26:f2:1f:52:41:04:71:d6:18:00:00:00:07:f4:26"
      )
}
