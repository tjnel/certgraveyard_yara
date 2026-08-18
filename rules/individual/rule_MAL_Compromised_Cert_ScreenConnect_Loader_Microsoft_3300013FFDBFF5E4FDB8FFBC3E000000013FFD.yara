import "pe"

rule MAL_Compromised_Cert_ScreenConnect_Loader_Microsoft_3300013FFDBFF5E4FDB8FFBC3E000000013FFD {
   meta:
      description         = "Detects ScreenConnect Loader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-21"
      version             = "1.0"

      hash                = "4faf038a0900962f06e8d20f9db26358bad631f2467f23b9bf707167208d357b"
      malware             = "ScreenConnect Loader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Ana leticia Lazcon"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:01:3f:fd:bf:f5:e4:fd:b8:ff:bc:3e:00:00:00:01:3f:fd"
      cert_thumbprint     = "2d35c2699dfc1260005234143017c654ceb94d89"
      cert_valid_from     = "2026-05-21"
      cert_valid_to       = "2026-05-24"

      country             = "US"
      state               = "Texas"
      locality            = "San Antonio"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:01:3f:fd:bf:f5:e4:fd:b8:ff:bc:3e:00:00:00:01:3f:fd"
      )
}
