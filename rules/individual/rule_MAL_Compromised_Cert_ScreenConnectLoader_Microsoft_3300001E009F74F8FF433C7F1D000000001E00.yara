import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_3300001E009F74F8FF433C7F1D000000001E00 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-16"
      version             = "1.0"

      hash                = "683b4d815aac916294629b1bc831b9572e7909eed8778705727f7c96cbce8b7e"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Palacios Edgar"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:00:1e:00:9f:74:f8:ff:43:3c:7f:1d:00:00:00:00:1e:00"
      cert_thumbprint     = "37834AF14F6BB05DF6FC9D67F7E06ED0026F4BB2"
      cert_valid_from     = "2026-04-16"
      cert_valid_to       = "2026-04-19"

      country             = "US"
      state               = "Texas"
      locality            = "San Antonio"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:00:1e:00:9f:74:f8:ff:43:3c:7f:1d:00:00:00:00:1e:00"
      )
}
