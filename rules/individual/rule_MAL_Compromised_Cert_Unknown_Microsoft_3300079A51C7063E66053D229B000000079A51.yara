import "pe"

rule MAL_Compromised_Cert_Unknown_Microsoft_3300079A51C7063E66053D229B000000079A51 {
   meta:
      description         = "Detects Unknown with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-16"
      version             = "1.0"

      hash                = "24857fe82f454719cd18bcbe19b0cfa5387bee1022008b7f5f3a8be9f05e4d14"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Donald Gay"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:07:9a:51:c7:06:3e:66:05:3d:22:9b:00:00:00:07:9a:51"
      cert_thumbprint     = "B674578D4BDB24CD58BF2DC884EAA658B7AA250C"
      cert_valid_from     = "2026-02-16"
      cert_valid_to       = "2026-02-19"

      country             = "US"
      state               = "Maryland"
      locality            = "Clinton"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:07:9a:51:c7:06:3e:66:05:3d:22:9b:00:00:00:07:9a:51"
      )
}
