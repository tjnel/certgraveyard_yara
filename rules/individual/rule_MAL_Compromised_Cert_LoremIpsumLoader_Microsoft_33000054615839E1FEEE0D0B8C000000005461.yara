import "pe"

rule MAL_Compromised_Cert_LoremIpsumLoader_Microsoft_33000054615839E1FEEE0D0B8C000000005461 {
   meta:
      description         = "Detects LoremIpsumLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-14"
      version             = "1.0"

      hash                = "a3467d8158e14ba6d86f46181da0cfd8143bb117087acf09d62243ecdcc60a82"
      malware             = "LoremIpsumLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "KELLY SULLIVAN"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:00:54:61:58:39:e1:fe:ee:0d:0b:8c:00:00:00:00:54:61"
      cert_thumbprint     = "8F45EE898F08464D0757BF685834297939457BB4"
      cert_valid_from     = "2026-04-14"
      cert_valid_to       = "2026-04-17"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:00:54:61:58:39:e1:fe:ee:0d:0b:8c:00:00:00:00:54:61"
      )
}
