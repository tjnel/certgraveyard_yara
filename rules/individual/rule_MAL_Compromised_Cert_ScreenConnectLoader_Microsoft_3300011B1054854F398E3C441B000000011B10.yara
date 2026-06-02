import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_3300011B1054854F398E3C441B000000011B10 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-16"
      version             = "1.0"

      hash                = "762c57c87ed6901c1a27beacf548ea5272e2b87e40a90eed2b9ad2576be42f41"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Morrison Chaunesey"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:01:1b:10:54:85:4f:39:8e:3c:44:1b:00:00:00:01:1b:10"
      cert_thumbprint     = "3EE519A095396CC81B9E55FA0A81B528029754FB"
      cert_valid_from     = "2026-05-16"
      cert_valid_to       = "2026-05-19"

      country             = "US"
      state               = "Texas"
      locality            = "Converse"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:01:1b:10:54:85:4f:39:8e:3c:44:1b:00:00:00:01:1b:10"
      )
}
