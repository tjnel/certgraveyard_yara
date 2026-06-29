import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330001E7B7B507DE1DE039761F00000001E7B7 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-09"
      version             = "1.0"

      hash                = "4edd29f7452b3ebd12d4c3ed0e92ff5288a0fd6073209e0b77afa2086b35bcdd"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Palacios Edgar"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:01:e7:b7:b5:07:de:1d:e0:39:76:1f:00:00:00:01:e7:b7"
      cert_thumbprint     = "AA64B3342A3F0F8DB654865BFEDE365E9D974875"
      cert_valid_from     = "2026-06-09"
      cert_valid_to       = "2026-06-12"

      country             = "US"
      state               = "Texas"
      locality            = "San Antonio"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:01:e7:b7:b5:07:de:1d:e0:39:76:1f:00:00:00:01:e7:b7"
      )
}
