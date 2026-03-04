import "pe"

rule MAL_Compromised_Cert_VariantLoader_Microsoft_330007D6C658F5D47885D0967800000007D6C6 {
   meta:
      description         = "Detects VariantLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-18"
      version             = "1.0"

      hash                = "4867245e221e4770e00abb3c4d5b4fe85c7e7c325b053ec3d88b776686f42f58"
      malware             = "VariantLoader"
      malware_type        = "Unknown"
      malware_notes       = "C2: 146.103.113.60"

      signer              = "JAMIE QUIGGINS"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:07:d6:c6:58:f5:d4:78:85:d0:96:78:00:00:00:07:d6:c6"
      cert_thumbprint     = "EA78EB54A97267F4D5850E25AA9DAC8C6DF6C403"
      cert_valid_from     = "2026-02-18"
      cert_valid_to       = "2026-02-21"

      country             = "US"
      state               = "California"
      locality            = "Los Angeles"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:07:d6:c6:58:f5:d4:78:85:d0:96:78:00:00:00:07:d6:c6"
      )
}
