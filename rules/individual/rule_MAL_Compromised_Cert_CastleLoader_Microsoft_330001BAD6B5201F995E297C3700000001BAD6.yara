import "pe"

rule MAL_Compromised_Cert_CastleLoader_Microsoft_330001BAD6B5201F995E297C3700000001BAD6 {
   meta:
      description         = "Detects CastleLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-05"
      version             = "1.0"

      hash                = "226cd36c2d1f002651aa8a4fcd20cb589029ec5605b2e256cac8472d4cb33d2a"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Elusive Techno"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:01:ba:d6:b5:20:1f:99:5e:29:7c:37:00:00:00:01:ba:d6"
      cert_thumbprint     = "2557A7D469BB72D304CA21E71EC168D2B45F4ACF"
      cert_valid_from     = "2026-06-05"
      cert_valid_to       = "2026-06-08"

      country             = "NL"
      state               = "Groningen"
      locality            = "Groningen"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:01:ba:d6:b5:20:1f:99:5e:29:7c:37:00:00:00:01:ba:d6"
      )
}
