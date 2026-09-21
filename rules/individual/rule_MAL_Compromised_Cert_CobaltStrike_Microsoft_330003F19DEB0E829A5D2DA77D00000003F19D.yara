import "pe"

rule MAL_Compromised_Cert_CobaltStrike_Microsoft_330003F19DEB0E829A5D2DA77D00000003F19D {
   meta:
      description         = "Detects CobaltStrike with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-08-05"
      version             = "1.0"

      hash                = "cc1004e7d470a657ff05f3363f2ee03cddb9342bc98091ceeabff40ef8fa331e"
      malware             = "CobaltStrike"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Alysen Mendez"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:03:f1:9d:eb:0e:82:9a:5d:2d:a7:7d:00:00:00:03:f1:9d"
      cert_thumbprint     = "36056f9bf9f822009cb3979053bb848e01f55ed4"
      cert_valid_from     = "2026-08-05"
      cert_valid_to       = "2026-08-08"

      country             = "US"
      state               = "New Jersey"
      locality            = "LITTLE FERRY"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:03:f1:9d:eb:0e:82:9a:5d:2d:a7:7d:00:00:00:03:f1:9d"
      )
}
