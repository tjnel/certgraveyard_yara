import "pe"

rule MAL_Compromised_Cert_Traffer_Microsoft_330006A011DA0B3E7233A75C1300000006A011 {
   meta:
      description         = "Detects Traffer with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-09"
      version             = "1.0"

      hash                = "49345d593cbce3d26fc4f400754c7da5d6f509a8470c3e5f0ad8429f9cb704f3"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Marker Hill Construction Inc"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:06:a0:11:da:0b:3e:72:33:a7:5c:13:00:00:00:06:a0:11"
      cert_thumbprint     = "F9BFF1C00522F8963ADC9B1DB3A3F1E39ECF793A"
      cert_valid_from     = "2025-12-09"
      cert_valid_to       = "2025-12-12"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:06:a0:11:da:0b:3e:72:33:a7:5c:13:00:00:00:06:a0:11"
      )
}
