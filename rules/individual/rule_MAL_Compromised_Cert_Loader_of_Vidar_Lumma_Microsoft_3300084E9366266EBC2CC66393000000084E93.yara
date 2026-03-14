import "pe"

rule MAL_Compromised_Cert_Loader_of_Vidar_Lumma_Microsoft_3300084E9366266EBC2CC66393000000084E93 {
   meta:
      description         = "Detects Loader of Vidar & Lumma with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-11"
      version             = "1.0"

      hash                = "f0a6b89ec7eee83274cd484cea526b970a3ef28038799b0a5774bb33c5793b55"
      malware             = "Loader of Vidar & Lumma"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Ramachandran Chollamuthu"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:08:4e:93:66:26:6e:bc:2c:c6:63:93:00:00:00:08:4e:93"
      cert_thumbprint     = "A3BBAA9445960F468BDB12F72707A3E9C6E76DC3"
      cert_valid_from     = "2026-03-11"
      cert_valid_to       = "2026-03-14"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:08:4e:93:66:26:6e:bc:2c:c6:63:93:00:00:00:08:4e:93"
      )
}
