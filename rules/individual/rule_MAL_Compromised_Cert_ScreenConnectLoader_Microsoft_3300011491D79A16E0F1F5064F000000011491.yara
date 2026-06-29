import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_3300011491D79A16E0F1F5064F000000011491 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-16"
      version             = "1.0"

      hash                = "018b8a293f578c971b08e84fb624d14837bcef849596d5905dcd3c719a335d05"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Chaunesey Morrison"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:01:14:91:d7:9a:16:e0:f1:f5:06:4f:00:00:00:01:14:91"
      cert_thumbprint     = "795D5E980D717B860A701FDF92B9C52CBB9BBA1C"
      cert_valid_from     = "2026-05-16"
      cert_valid_to       = "2026-05-19"

      country             = "US"
      state               = "Texas"
      locality            = "converse"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:01:14:91:d7:9a:16:e0:f1:f5:06:4f:00:00:00:01:14:91"
      )
}
