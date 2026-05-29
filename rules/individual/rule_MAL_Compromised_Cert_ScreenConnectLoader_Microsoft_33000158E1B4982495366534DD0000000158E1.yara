import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_33000158E1B4982495366534DD0000000158E1 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-25"
      version             = "1.0"

      hash                = "9fbbbc0f5da75fc765e9b361ca6d81df589a5d4a4206d8f8bcf9345c7913057d"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Sabrina Perry"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:01:58:e1:b4:98:24:95:36:65:34:dd:00:00:00:01:58:e1"
      cert_thumbprint     = "9053807C49699B17342C1C78AD91AD82A1F9BC81"
      cert_valid_from     = "2026-05-25"
      cert_valid_to       = "2026-05-28"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:01:58:e1:b4:98:24:95:36:65:34:dd:00:00:00:01:58:e1"
      )
}
