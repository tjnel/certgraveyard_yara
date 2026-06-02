import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_3300001D53DB71F6B6F02C3FCA000000001D53 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-15"
      version             = "1.0"

      hash                = "4ba5791fa688cebc92062dbd0e9b1c02d7f44e0e49648349516b37f5455309d8"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Palacios Edgar"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:00:1d:53:db:71:f6:b6:f0:2c:3f:ca:00:00:00:00:1d:53"
      cert_thumbprint     = "4F20647E9DE362951C9370E57354E62F71E03138"
      cert_valid_from     = "2026-04-15"
      cert_valid_to       = "2026-04-18"

      country             = "---"
      state               = "---"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:00:1d:53:db:71:f6:b6:f0:2c:3f:ca:00:00:00:00:1d:53"
      )
}
