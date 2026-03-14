import "pe"

rule MAL_Compromised_Cert_Loader_of_Vidar_Lumma_Microsoft_3300076E1C86261F5709D3F421000000076E1C {
   meta:
      description         = "Detects Loader of Vidar & Lumma with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-13"
      version             = "1.0"

      hash                = "c7c5072df9f83f4c440a5c3bb4be1d5f6c67bbf78f196406ca20d27b43b975b8"
      malware             = "Loader of Vidar & Lumma"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Sandra Harrison"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:07:6e:1c:86:26:1f:57:09:d3:f4:21:00:00:00:07:6e:1c"
      cert_thumbprint     = "4F5C5B3EF45CFFF7721754487A86AEFF9A2E6E32"
      cert_valid_from     = "2026-03-13"
      cert_valid_to       = "2026-03-16"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:07:6e:1c:86:26:1f:57:09:d3:f4:21:00:00:00:07:6e:1c"
      )
}
