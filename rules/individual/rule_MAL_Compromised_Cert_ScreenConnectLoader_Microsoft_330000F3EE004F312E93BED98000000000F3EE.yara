import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330000F3EE004F312E93BED98000000000F3EE {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-13"
      version             = "1.0"

      hash                = "dc6e23b3050e75b2bc28dd5c5f702e90ff18c1c927d3775fd5f95d3116a97e1a"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Chaunesey Morrison"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:00:f3:ee:00:4f:31:2e:93:be:d9:80:00:00:00:00:f3:ee"
      cert_thumbprint     = "C8F8A9947E5DE4D09566FE7F590CD2C53F5CEEA7"
      cert_valid_from     = "2026-05-13"
      cert_valid_to       = "2026-05-16"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:00:f3:ee:00:4f:31:2e:93:be:d9:80:00:00:00:00:f3:ee"
      )
}
