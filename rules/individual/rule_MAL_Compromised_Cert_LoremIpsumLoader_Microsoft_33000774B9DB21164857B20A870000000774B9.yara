import "pe"

rule MAL_Compromised_Cert_LoremIpsumLoader_Microsoft_33000774B9DB21164857B20A870000000774B9 {
   meta:
      description         = "Detects LoremIpsumLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-16"
      version             = "1.0"

      hash                = "56c897138ad7923110bf4e296b0e9cfc49d5fe09685f1fd7d5a6db46edb33632"
      malware             = "LoremIpsumLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "KEVIN PAGE"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:07:74:b9:db:21:16:48:57:b2:0a:87:00:00:00:07:74:b9"
      cert_thumbprint     = "CB5ED4A537E0435BF7249E63FD22C13576D0FFBE"
      cert_valid_from     = "2026-03-16"
      cert_valid_to       = "2026-03-19"

      country             = "US"
      state               = "California"
      locality            = "LOS ANGELES"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:07:74:b9:db:21:16:48:57:b2:0a:87:00:00:00:07:74:b9"
      )
}
