import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330008949836546D9A34F18763000000089498 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-19"
      version             = "1.0"

      hash                = "6061306ac9b67a07e27359d0c0f25155ef2fc55d383815b6a348124ede7bdefc"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Palacios Edgar"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:08:94:98:36:54:6d:9a:34:f1:87:63:00:00:00:08:94:98"
      cert_thumbprint     = "613B01965F16D5ECD5C15DB7A854BC861F9BAA30"
      cert_valid_from     = "2026-03-19"
      cert_valid_to       = "2026-03-22"

      country             = "US"
      state               = "Texas"
      locality            = "San Antonio"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:08:94:98:36:54:6d:9a:34:f1:87:63:00:00:00:08:94:98"
      )
}
