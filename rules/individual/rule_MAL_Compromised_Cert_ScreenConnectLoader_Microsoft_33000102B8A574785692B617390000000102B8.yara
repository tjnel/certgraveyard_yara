import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_33000102B8A574785692B617390000000102B8 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-14"
      version             = "1.0"

      hash                = "6777bf31fcecd2c073b27cbef8af264bc4b51b43695c98712f66af47be283598"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Avery Benavidez"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:01:02:b8:a5:74:78:56:92:b6:17:39:00:00:00:01:02:b8"
      cert_thumbprint     = "59C5A40C971AC49E3CE48CA6D5C9CF37D6CA3CD7"
      cert_valid_from     = "2026-05-14"
      cert_valid_to       = "2026-05-17"

      country             = "US"
      state               = "Texas"
      locality            = "San Antonio"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:01:02:b8:a5:74:78:56:92:b6:17:39:00:00:00:01:02:b8"
      )
}
