import "pe"

rule MAL_Compromised_Cert_Traffer_Microsoft_33000898DCD27E0B07276CB3680000000898DC {
   meta:
      description         = "Detects Traffer with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-20"
      version             = "1.0"

      hash                = "5202a88b6257d8532fce5cfac36957434839040e2257570025bdc99cad9a4532"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Marker Hill Construction Inc"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:08:98:dc:d2:7e:0b:07:27:6c:b3:68:00:00:00:08:98:dc"
      cert_thumbprint     = "5DE524C8E79C25C28F35D696F753963AE83DAFC2"
      cert_valid_from     = "2026-03-20"
      cert_valid_to       = "2026-03-23"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:08:98:dc:d2:7e:0b:07:27:6c:b3:68:00:00:00:08:98:dc"
      )
}
