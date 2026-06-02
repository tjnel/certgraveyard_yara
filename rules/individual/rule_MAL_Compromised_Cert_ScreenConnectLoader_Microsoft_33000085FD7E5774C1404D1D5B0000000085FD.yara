import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_33000085FD7E5774C1404D1D5B0000000085FD {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-26"
      version             = "1.0"

      hash                = "ce0aed3ced478e254471405546d2325d473d2feb4ff51b3f352e79cb8ac2036e"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Ana leticia Lazcon"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:00:85:fd:7e:57:74:c1:40:4d:1d:5b:00:00:00:00:85:fd"
      cert_thumbprint     = "272DF1213990FDDD777A0688225C2DB468C9C91D"
      cert_valid_from     = "2026-04-26"
      cert_valid_to       = "2026-04-29"

      country             = "US"
      state               = "Texas"
      locality            = "San Antonio"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:00:85:fd:7e:57:74:c1:40:4d:1d:5b:00:00:00:00:85:fd"
      )
}
