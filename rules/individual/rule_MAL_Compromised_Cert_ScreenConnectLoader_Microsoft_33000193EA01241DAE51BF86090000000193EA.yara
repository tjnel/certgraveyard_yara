import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_33000193EA01241DAE51BF86090000000193EA {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-01"
      version             = "1.0"

      hash                = "90744f72236554fb7a1f1c218f42c55e16d6d1460fd364656c7cada554282fb7"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Danielle Hale"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:01:93:ea:01:24:1d:ae:51:bf:86:09:00:00:00:01:93:ea"
      cert_thumbprint     = "BCBEEA59A52D084DC7883374ABB41E39396E2A44"
      cert_valid_from     = "2026-06-01"
      cert_valid_to       = "2026-06-04"

      country             = "US"
      state               = "oh"
      locality            = "Cleveland"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:01:93:ea:01:24:1d:ae:51:bf:86:09:00:00:00:01:93:ea"
      )
}
