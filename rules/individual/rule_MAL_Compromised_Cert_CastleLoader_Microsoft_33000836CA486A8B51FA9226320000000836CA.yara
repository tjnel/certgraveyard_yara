import "pe"

rule MAL_Compromised_Cert_CastleLoader_Microsoft_33000836CA486A8B51FA9226320000000836CA {
   meta:
      description         = "Detects CastleLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-07"
      version             = "1.0"

      hash                = "b30f4605e181fc71c339131d0b8d104d337d23fd9707b6939ef8933e7c434f05"
      malware             = "CastleLoader"
      malware_type        = "Initial access tool"
      malware_notes       = ""

      signer              = "JAMIE QUIGGINS"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:08:36:ca:48:6a:8b:51:fa:92:26:32:00:00:00:08:36:ca"
      cert_thumbprint     = "E0CE5A2A4AD8817538783AB7BA3EA89C844D2C77"
      cert_valid_from     = "2026-03-07"
      cert_valid_to       = "2026-03-10"

      country             = "US"
      state               = "California"
      locality            = "Los Angeles"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:08:36:ca:48:6a:8b:51:fa:92:26:32:00:00:00:08:36:ca"
      )
}
