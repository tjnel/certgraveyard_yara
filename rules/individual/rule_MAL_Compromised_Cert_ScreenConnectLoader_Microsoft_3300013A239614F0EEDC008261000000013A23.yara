import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_3300013A239614F0EEDC008261000000013A23 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-20"
      version             = "1.0"

      hash                = "601f4ae850e192bc76300f3851f4b421ba2e05313cb3f1ace0a0c98301e237bb"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Alysen Mendez"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:01:3a:23:96:14:f0:ee:dc:00:82:61:00:00:00:01:3a:23"
      cert_thumbprint     = "6EA39ED2E1954F1148DE2CA2A68F2C256F71C8FD"
      cert_valid_from     = "2026-05-20"
      cert_valid_to       = "2026-05-23"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:01:3a:23:96:14:f0:ee:dc:00:82:61:00:00:00:01:3a:23"
      )
}
