import "pe"

rule MAL_Compromised_Cert_ScreenConnect_Loader_Microsoft_330001A5A3233B73269302AECF00000001A5A3 {
   meta:
      description         = "Detects ScreenConnect Loader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-03"
      version             = "1.0"

      hash                = "00489ef4d50d368d4b8b99ee58a635ffd9cf23ba777f8db5c958e685decc3e94"
      malware             = "ScreenConnect Loader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Paula Foster"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:01:a5:a3:23:3b:73:26:93:02:ae:cf:00:00:00:01:a5:a3"
      cert_thumbprint     = "d9fac2f21b57244dbe8aa434f9a8a2d63c8d96d9"
      cert_valid_from     = "2026-06-03"
      cert_valid_to       = "2026-06-06"

      country             = "US"
      state               = "fl"
      locality            = "Saint James City"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:01:a5:a3:23:3b:73:26:93:02:ae:cf:00:00:00:01:a5:a3"
      )
}
