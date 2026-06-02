import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330000D2D7D71FE608C242E81500000000D2D7 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-08"
      version             = "1.0"

      hash                = "ba6fb57e93fbb3fb7d3556173f262b05ff738961dda228b5f3fe451bdce4eeb8"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Morrison Chaunesey"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:00:d2:d7:d7:1f:e6:08:c2:42:e8:15:00:00:00:00:d2:d7"
      cert_thumbprint     = "FE8DB03F4F35D807EBCC03250B8B9C56A23E53E2"
      cert_valid_from     = "2026-05-08"
      cert_valid_to       = "2026-05-11"

      country             = "---"
      state               = "---"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:00:d2:d7:d7:1f:e6:08:c2:42:e8:15:00:00:00:00:d2:d7"
      )
}
