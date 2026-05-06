import "pe"

rule MAL_Compromised_Cert_VariantLoader_Microsoft_330000BF23570CDE3B2895388700000000BF23 {
   meta:
      description         = "Detects VariantLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-04"
      version             = "1.0"

      hash                = "a344e04cbbacd1077002a941fff703f036bf5dc45b0d993d62aafda8ea3e3e03"
      malware             = "VariantLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SERPENTINE SOLAR LIMITED"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:00:bf:23:57:0c:de:3b:28:95:38:87:00:00:00:00:bf:23"
      cert_thumbprint     = "9A315189BF3AB595439D484D0BFD0D85ADC9EB91"
      cert_valid_from     = "2026-05-04"
      cert_valid_to       = "2026-05-07"

      country             = "IE"
      state               = "Dublin"
      locality            = "Dublin"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:00:bf:23:57:0c:de:3b:28:95:38:87:00:00:00:00:bf:23"
      )
}
