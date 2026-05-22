import "pe"

rule MAL_Compromised_Cert_VariantLoader_Microsoft_330007EB5E04CA0E6EBDA0E14100000007EB5E {
   meta:
      description         = "Detects VariantLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-06"
      version             = "1.0"

      hash                = "a730609b54dc1e57fba7d537ef3ecd9da760731d9c1f05054eed0b694eccd225"
      malware             = "VariantLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "TECHNOLOGY APPRAISALS LIMITED"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:07:eb:5e:04:ca:0e:6e:bd:a0:e1:41:00:00:00:07:eb:5e"
      cert_thumbprint     = "90B1B6A769D7F39B0D880E515526810818B7EE13"
      cert_valid_from     = "2026-04-06"
      cert_valid_to       = "2026-04-09"

      country             = "GB"
      state               = "Midlothian"
      locality            = "TWICKENHAM"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:07:eb:5e:04:ca:0e:6e:bd:a0:e1:41:00:00:00:07:eb:5e"
      )
}
