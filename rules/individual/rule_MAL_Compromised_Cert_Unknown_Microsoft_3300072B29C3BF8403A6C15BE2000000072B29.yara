import "pe"

rule MAL_Compromised_Cert_Unknown_Microsoft_3300072B29C3BF8403A6C15BE2000000072B29 {
   meta:
      description         = "Detects Unknown with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-01"
      version             = "1.0"

      hash                = "64263640a6fdeb2388bca2e9094a17065308cf8dcb0032454c0a71d9b78327eb"
      malware             = "Unknown"
      malware_type        = "Initial access tool"
      malware_notes       = "File is disguised as Obsidian installer, uses python script to pull down second stage payload."

      signer              = "Donald Gay"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:07:2b:29:c3:bf:84:03:a6:c1:5b:e2:00:00:00:07:2b:29"
      cert_thumbprint     = "F8444DFC740B94227AB9B2E757B8F8F1FA49362A"
      cert_valid_from     = "2026-03-01"
      cert_valid_to       = "2026-03-04"

      country             = "US"
      state               = "Maryland"
      locality            = "Clinton"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:07:2b:29:c3:bf:84:03:a6:c1:5b:e2:00:00:00:07:2b:29"
      )
}
