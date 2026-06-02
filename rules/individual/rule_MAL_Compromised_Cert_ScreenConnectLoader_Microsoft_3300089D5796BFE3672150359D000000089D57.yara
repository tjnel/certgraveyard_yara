import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_3300089D5796BFE3672150359D000000089D57 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-31"
      version             = "1.0"

      hash                = "883d9209b1f866445944debeb56bd6b6f4f0baa3088768b7dd5c18878c898f8b"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Sharp Tavyn"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:08:9d:57:96:bf:e3:67:21:50:35:9d:00:00:00:08:9d:57"
      cert_thumbprint     = "A7308C1589FD9B2149254C32BA2A1FF58BA895BC"
      cert_valid_from     = "2026-03-31"
      cert_valid_to       = "2026-04-03"

      country             = "US"
      state               = "Oklahoma"
      locality            = "Ringling"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:08:9d:57:96:bf:e3:67:21:50:35:9d:00:00:00:08:9d:57"
      )
}
