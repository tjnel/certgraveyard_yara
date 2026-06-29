import "pe"

rule MAL_Compromised_Cert_CastleLoader_Microsoft_33000228C933B5DFD616416FCD0000000228C9 {
   meta:
      description         = "Detects CastleLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-15"
      version             = "1.0"

      hash                = "824f559b153c8c13bf1ba49fc96e384ba4117070ebad4e782e56a056a69ac906"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Table for Len"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:02:28:c9:33:b5:df:d6:16:41:6f:cd:00:00:00:02:28:c9"
      cert_thumbprint     = "EEA0042D8E2A4952E4E3D2552DA5431B8AA0BB0C"
      cert_valid_from     = "2026-06-15"
      cert_valid_to       = "2026-06-18"

      country             = "NL"
      state               = "Noord-Holland"
      locality            = "Amsterdam"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:02:28:c9:33:b5:df:d6:16:41:6f:cd:00:00:00:02:28:c9"
      )
}
