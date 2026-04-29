import "pe"

rule MAL_Compromised_Cert_Remcos_RAT_Microsoft_330000843F3A83AD6D5353199400000000843F {
   meta:
      description         = "Detects Remcos RAT with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-26"
      version             = "1.0"

      hash                = "f6f7d15736d0b0dbb3e6f3fabafd28ccfdb300466d4337781b8a2542221dc71d"
      malware             = "Remcos RAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "ENGINEERING AND TECHNICAL PROCUREMENT SERVICES LTD"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:00:84:3f:3a:83:ad:6d:53:53:19:94:00:00:00:00:84:3f"
      cert_thumbprint     = "E2E96A73DDE8E076FCBF98E6ACCBD80E4A9B4244"
      cert_valid_from     = "2026-04-26"
      cert_valid_to       = "2026-04-29"

      country             = "GB"
      state               = "Essex"
      locality            = "Hadleigh"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:00:84:3f:3a:83:ad:6d:53:53:19:94:00:00:00:00:84:3f"
      )
}
