import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_3300010036E66660B03E5DC1FD000000010036 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-14"
      version             = "1.0"

      hash                = "9dfec319c80b3314a8de20821d0e2e0b00283e04fac4723f3a48628784c600d8"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Chaunesey Morrison"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:01:00:36:e6:66:60:b0:3e:5d:c1:fd:00:00:00:01:00:36"
      cert_thumbprint     = "79AE61F5FECC52BEC38EE2D8B7358586DE5F558A"
      cert_valid_from     = "2026-05-14"
      cert_valid_to       = "2026-05-17"

      country             = "US"
      state               = "Texas"
      locality            = "converse"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:01:00:36:e6:66:60:b0:3e:5d:c1:fd:00:00:00:01:00:36"
      )
}
