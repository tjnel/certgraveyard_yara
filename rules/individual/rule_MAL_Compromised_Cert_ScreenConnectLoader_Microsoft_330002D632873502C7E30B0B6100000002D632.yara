import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330002D632873502C7E30B0B6100000002D632 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-07-08"
      version             = "1.0"

      hash                = "de63e613dee432601f67650b0fdd2d4cebe88838b6ba180fe5702686585c17a1"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "jasmine mosby"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:02:d6:32:87:35:02:c7:e3:0b:0b:61:00:00:00:02:d6:32"
      cert_thumbprint     = "CECFDF7E23E6DD65DC0D06EE6D0D48BD3C117D6B"
      cert_valid_from     = "2026-07-08"
      cert_valid_to       = "2026-07-11"

      country             = "US"
      state               = "ar"
      locality            = "Little Rock"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:02:d6:32:87:35:02:c7:e3:0b:0b:61:00:00:00:02:d6:32"
      )
}
