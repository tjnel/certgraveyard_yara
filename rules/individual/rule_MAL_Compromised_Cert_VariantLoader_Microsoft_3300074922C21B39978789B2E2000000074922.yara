import "pe"

rule MAL_Compromised_Cert_VariantLoader_Microsoft_3300074922C21B39978789B2E2000000074922 {
   meta:
      description         = "Detects VariantLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-06"
      version             = "1.0"

      hash                = "4bb1a9591d047673fb0fbad3d7c41c2d55fbaeaeab26a61a205d278204316f7b"
      malware             = "VariantLoader"
      malware_type        = "Unknown"
      malware_notes       = "C2: 146.103.113.60"

      signer              = "Marni Hirschorn"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:07:49:22:c2:1b:39:97:87:89:b2:e2:00:00:00:07:49:22"
      cert_thumbprint     = "EA176B091FC6EE2656B72E1F9408FF99690E4125"
      cert_valid_from     = "2026-03-06"
      cert_valid_to       = "2026-03-09"

      country             = "US"
      state               = "New Jersey"
      locality            = "Woodcliff Lake"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:07:49:22:c2:1b:39:97:87:89:b2:e2:00:00:00:07:49:22"
      )
}
