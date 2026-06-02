import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_3300006A24D0310773536D9115000000006A24 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-22"
      version             = "1.0"

      hash                = "62e6cc9a6531be22315cc4387fd67936d02630e2de1d024ce357d9d1fc53e49a"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Palacios Edgar"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:00:6a:24:d0:31:07:73:53:6d:91:15:00:00:00:00:6a:24"
      cert_thumbprint     = "D7F7F1170A97F237F22AB3AB36CDF0A65ABCFBB1"
      cert_valid_from     = "2026-04-22"
      cert_valid_to       = "2026-04-25"

      country             = "US"
      state               = "Texas"
      locality            = "San Antonio"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:00:6a:24:d0:31:07:73:53:6d:91:15:00:00:00:00:6a:24"
      )
}
