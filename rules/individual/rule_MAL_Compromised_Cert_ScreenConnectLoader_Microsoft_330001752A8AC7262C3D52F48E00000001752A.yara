import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330001752A8AC7262C3D52F48E00000001752A {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-29"
      version             = "1.0"

      hash                = "5d9e41a6e2bb4e4255184bff952b538dfca628a6a5b5c4a822601011c52a78db"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Sabrina Perry"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:01:75:2a:8a:c7:26:2c:3d:52:f4:8e:00:00:00:01:75:2a"
      cert_thumbprint     = "DB824D1849CBFD9D1E658CB6B71CAA7A10FEAC3C"
      cert_valid_from     = "2026-05-29"
      cert_valid_to       = "2026-06-01"

      country             = "US"
      state               = "hi"
      locality            = "Wailuku"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:01:75:2a:8a:c7:26:2c:3d:52:f4:8e:00:00:00:01:75:2a"
      )
}
