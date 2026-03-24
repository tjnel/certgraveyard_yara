import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330008568D4A72F36727C1360000000008568D {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-18"
      version             = "1.0"

      hash                = "a3ac637f33bb3945aa82d53f8579f618ceb664d9b714cb667fdd9bbfa5337266"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Perry Sabrina Ann"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:08:56:8d:4a:72:f3:67:27:c1:36:00:00:00:00:08:56:8d"
      cert_thumbprint     = "524A4BC321382EA4F1DA705B96068D2517D1EC52"
      cert_valid_from     = "2026-03-18"
      cert_valid_to       = "2026-03-21"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:08:56:8d:4a:72:f3:67:27:c1:36:00:00:00:00:08:56:8d"
      )
}
