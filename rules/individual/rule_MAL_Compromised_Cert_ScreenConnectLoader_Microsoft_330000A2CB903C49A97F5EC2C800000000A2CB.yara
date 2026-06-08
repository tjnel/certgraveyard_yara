import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330000A2CB903C49A97F5EC2C800000000A2CB {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-30"
      version             = "1.0"

      hash                = "227c0b52e08d524c703ecde3da2c7dbfee350a716f5d66030dfd265d4d722457"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Ana Lazcon"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:00:a2:cb:90:3c:49:a9:7f:5e:c2:c8:00:00:00:00:a2:cb"
      cert_thumbprint     = "2351C35CCA80AE01FF6352AE6567B7C686CCD371"
      cert_valid_from     = "2026-04-30"
      cert_valid_to       = "2026-05-03"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:00:a2:cb:90:3c:49:a9:7f:5e:c2:c8:00:00:00:00:a2:cb"
      )
}
