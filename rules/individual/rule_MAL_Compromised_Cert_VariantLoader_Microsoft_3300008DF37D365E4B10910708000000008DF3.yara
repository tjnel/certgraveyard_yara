import "pe"

rule MAL_Compromised_Cert_VariantLoader_Microsoft_3300008DF37D365E4B10910708000000008DF3 {
   meta:
      description         = "Detects VariantLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-27"
      version             = "1.0"

      hash                = "5735af68fc8e56edf0e5d1b154f9fa7db1bffaa685360c3e2e4feaac86a0fc92"
      malware             = "VariantLoader"
      malware_type        = "Unknown"
      malware_notes       = "C2: 185.219.83.213"

      signer              = "OC Agro ApS"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:00:8d:f3:7d:36:5e:4b:10:91:07:08:00:00:00:00:8d:f3"
      cert_thumbprint     = "BA55DA6445D16C73D8F3BAC1CB22E384807847B3"
      cert_valid_from     = "2026-04-27"
      cert_valid_to       = "2026-04-30"

      country             = "DK"
      state               = "Central Jutland"
      locality            = "Hammel"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:00:8d:f3:7d:36:5e:4b:10:91:07:08:00:00:00:00:8d:f3"
      )
}
