import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330001CC4F247D95E6984F96FD00000001CC4F {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-07"
      version             = "1.0"

      hash                = "bb4409077a98a8d8e02a008d6f64f98e6376624860ea871de7e983a5882213c6"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Palacios Edgar"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:01:cc:4f:24:7d:95:e6:98:4f:96:fd:00:00:00:01:cc:4f"
      cert_thumbprint     = "FC6D58E07AF6FA9CED5A66D32516E585075ACE6C"
      cert_valid_from     = "2026-06-07"
      cert_valid_to       = "2026-06-10"

      country             = "US"
      state               = "Texas"
      locality            = "San Antonio"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:01:cc:4f:24:7d:95:e6:98:4f:96:fd:00:00:00:01:cc:4f"
      )
}
