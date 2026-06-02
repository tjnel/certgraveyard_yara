import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_3300008720524A68406CFC8DFF000000008720 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-27"
      version             = "1.0"

      hash                = "b6df612bb7d5ace42dde016306c210b819d90df44424548a2ac174e0e1c80fa3"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Sharp Tavyn"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:00:87:20:52:4a:68:40:6c:fc:8d:ff:00:00:00:00:87:20"
      cert_thumbprint     = "FCD128FE78334BDFFFBF215EEB2DED1ED30C5308"
      cert_valid_from     = "2026-04-27"
      cert_valid_to       = "2026-04-30"

      country             = "US"
      state               = "Oklahoma"
      locality            = "Ringling"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:00:87:20:52:4a:68:40:6c:fc:8d:ff:00:00:00:00:87:20"
      )
}
