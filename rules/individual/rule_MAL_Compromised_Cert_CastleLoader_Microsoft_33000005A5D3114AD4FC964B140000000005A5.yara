import "pe"

rule MAL_Compromised_Cert_CastleLoader_Microsoft_33000005A5D3114AD4FC964B140000000005A5 {
   meta:
      description         = "Detects CastleLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-09"
      version             = "1.0"

      hash                = "018591f165b83247db10620d5b45a31ba406c10a5f85a6c2c30d297b530774ee"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LEXYL EPSILON"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:00:05:a5:d3:11:4a:d4:fc:96:4b:14:00:00:00:00:05:a5"
      cert_thumbprint     = "A4AAA29CAABB5D0ED723EDEFD164FAEB059383F6"
      cert_valid_from     = "2026-04-09"
      cert_valid_to       = "2026-04-12"

      country             = "US"
      state               = "Alaska"
      locality            = "ANCHORAGE"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:00:05:a5:d3:11:4a:d4:fc:96:4b:14:00:00:00:00:05:a5"
      )
}
