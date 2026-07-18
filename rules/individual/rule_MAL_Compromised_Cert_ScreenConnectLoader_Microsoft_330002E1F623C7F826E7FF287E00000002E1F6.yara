import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330002E1F623C7F826E7FF287E00000002E1F6 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-07-09"
      version             = "1.0"

      hash                = "e80fa0d102439b27b894e18c18c1465c60a568271a95655ceb6435e03e476017"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "jasmine mosby"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:02:e1:f6:23:c7:f8:26:e7:ff:28:7e:00:00:00:02:e1:f6"
      cert_thumbprint     = "A65EA86FAA5F5C6131B0116C658443E5307C0EA3"
      cert_valid_from     = "2026-07-09"
      cert_valid_to       = "2026-07-12"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:02:e1:f6:23:c7:f8:26:e7:ff:28:7e:00:00:00:02:e1:f6"
      )
}
