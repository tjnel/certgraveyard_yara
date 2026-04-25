import "pe"

rule MAL_Compromised_Cert_LoremIpsumLoader_Microsoft_33000061B367BF2AAE2472836D0000000061B3 {
   meta:
      description         = "Detects LoremIpsumLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-21"
      version             = "1.0"

      hash                = "a7dfe696c8c5b2c0fe8ac4d525e0fe13173af727204a0727a4014199c64bab11"
      malware             = "LoremIpsumLoader"
      malware_type        = "Initial access tool"
      malware_notes       = ""

      signer              = "SHYANNE COLLINS"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:00:61:b3:67:bf:2a:ae:24:72:83:6d:00:00:00:00:61:b3"
      cert_thumbprint     = "2D947828A705C451E74BB38984B1069BB289E335"
      cert_valid_from     = "2026-04-21"
      cert_valid_to       = "2026-04-24"

      country             = "US"
      state               = "Arkansas"
      locality            = "MORRILTON"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:00:61:b3:67:bf:2a:ae:24:72:83:6d:00:00:00:00:61:b3"
      )
}
