import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_33000825AD34361AD3BE05732D0000000825AD {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-13"
      version             = "1.0"

      hash                = "eadc7959647df5845e511e7c2a61751f7063c2fc73a11f513637cff7afa2acca"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Stephen Palmer"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:08:25:ad:34:36:1a:d3:be:05:73:2d:00:00:00:08:25:ad"
      cert_thumbprint     = "4DCC7478EDAD3B813FFCC8A8202363300018811C"
      cert_valid_from     = "2026-03-13"
      cert_valid_to       = "2026-03-16"

      country             = "US"
      state               = "Georgia"
      locality            = "Villa Rica"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:08:25:ad:34:36:1a:d3:be:05:73:2d:00:00:00:08:25:ad"
      )
}
